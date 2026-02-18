// fuzz_dataops.cpp — Fuzzer for CPython's data-structure C extension modules.
//
// This fuzzer exercises the following CPython C extension modules via
// their Python API, called through the Python C API from C++:
//
//   array               — array(typecode) with frombytes, tobytes, tolist,
//                          reverse, byteswap, append, extend, pop, count,
//                          index, insert, remove, buffer_info, __sizeof__,
//                          __contains__, __iter__, slice ops, comparison,
//                          concatenation, repetition, fromlist
//   _ctypes             — c_char/c_int/c_double.from_buffer_copy(),
//                          create_string_buffer, (c_char*N).from_buffer_copy,
//                          Structure.from_buffer_copy
//   mmap                — anonymous mmap: write, find, rfind, read, readline,
//                          seek, resize, move, getitem, setitem, flush, size,
//                          tell, close, context manager
//   _locale             — strxfrm, strcoll
//   _dbm                — dbm.open, write, read, keys, delete, iteration
//   _sqlite3            — connect(':memory:'), execute, executemany,
//                          executescript, complete_statement, create_function,
//                          create_aggregate, set_authorizer, create_collation,
//                          Row factory, blobopen, register_adapter
//
// The first byte of fuzz input selects one of 9 operation types. Each
// operation consumes further bytes via FuzzedDataProvider to parameterize
// the call (typecode, sub-operation, SQL, key/value splits).
//
// All module functions and class constructors are imported once during init
// and cached as static PyObject* pointers. Two helper classes (Structure
// subclass, Aggregate class) are defined via PyRun_String at init time.
// PyRef (RAII) prevents reference leaks. PyGC_Collect() runs every 200
// iterations. Max input size: 64 KB.

#include "fuzz_helpers.h"

// ---------------------------------------------------------------------------
// Cached module objects, initialized once.
// ---------------------------------------------------------------------------

// array
static PyObject *array_array;

// ctypes
static PyObject *ct_c_char, *ct_c_int, *ct_c_double;
static PyObject *ct_create_string_buffer, *ct_sizeof;
static PyObject *ct_Structure_cls;

// mmap
static PyObject *mmap_mmap;

// locale
static PyObject *locale_strxfrm, *locale_strcoll;

// dbm
static PyObject *dbm_open;

// sqlite3
static PyObject *sqlite3_connect, *sqlite3_complete_statement;
static PyObject *sqlite3_register_adapter, *sqlite3_Row;
static long sqlite3_SQLITE_OK_val;
static PyObject *sqlite3_Aggregate_cls;

static unsigned long gc_counter = 0;

static int initialized = 0;

static void init_dataops(void) {
  if (initialized) return;

  // array
  array_array = import_attr("array", "array");

  // ctypes
  ct_c_char = import_attr("ctypes", "c_char");
  ct_c_int = import_attr("ctypes", "c_int");
  ct_c_double = import_attr("ctypes", "c_double");
  ct_create_string_buffer = import_attr("ctypes", "create_string_buffer");
  ct_sizeof = import_attr("ctypes", "sizeof");

  // ctypes Structure subclass.
  {
    PyObject *globals = PyDict_New();
    PyDict_SetItemString(globals, "__builtins__", PyEval_GetBuiltins());
    PyObject *r = PyRun_String(
        "import ctypes\n"
        "class _S(ctypes.Structure):\n"
        "    _fields_ = [('a', ctypes.c_int), ('b', ctypes.c_double)]\n",
        Py_file_input, globals, globals);
    if (!r) { PyErr_Print(); abort(); }
    Py_DECREF(r);
    ct_Structure_cls = PyDict_GetItemString(globals, "_S");
    Py_INCREF(ct_Structure_cls);
    Py_DECREF(globals);
  }

  // mmap
  mmap_mmap = import_attr("mmap", "mmap");

  // locale
  locale_strxfrm = import_attr("locale", "strxfrm");
  locale_strcoll = import_attr("locale", "strcoll");

  // dbm
  dbm_open = import_attr("dbm", "open");

  // sqlite3
  sqlite3_connect = import_attr("sqlite3", "connect");
  sqlite3_complete_statement = import_attr("sqlite3", "complete_statement");
  sqlite3_register_adapter = import_attr("sqlite3", "register_adapter");
  sqlite3_Row = import_attr("sqlite3", "Row");
  {
    PyObject *v = import_attr("sqlite3", "SQLITE_OK");
    sqlite3_SQLITE_OK_val = PyLong_AsLong(v);
    Py_DECREF(v);
  }

  // Aggregate class for sqlite3.
  {
    PyObject *globals = PyDict_New();
    PyDict_SetItemString(globals, "__builtins__", PyEval_GetBuiltins());
    PyObject *r = PyRun_String(
        "class _Agg:\n"
        "    def __init__(self): self.vals = []\n"
        "    def step(self, v): self.vals.append(v)\n"
        "    def finalize(self): return len(self.vals)\n",
        Py_file_input, globals, globals);
    if (!r) { PyErr_Print(); abort(); }
    Py_DECREF(r);
    sqlite3_Aggregate_cls = PyDict_GetItemString(globals, "_Agg");
    Py_INCREF(sqlite3_Aggregate_cls);
    Py_DECREF(globals);
  }

  // Suppress warnings.
  PyRun_SimpleString("import warnings; warnings.filterwarnings('ignore')");

  assert(!PyErr_Occurred());
  initialized = 1;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Item sizes for array typecodes.
static int typecode_itemsize(char tc) {
  switch (tc) {
    case 'b': case 'B': return 1;
    case 'H': return 2;
    case 'i': case 'I': case 'l': case 'L': case 'f': return 4;
    case 'd': case 'q': case 'Q': return 8;
    default: return 1;
  }
}

// Create an array with the given typecode and aligned data.
static PyObject *make_array(char tc, const std::string &data) {
  int item_sz = typecode_itemsize(tc);
  size_t aligned_len = (data.size() / item_sz) * item_sz;
  if (aligned_len == 0) aligned_len = item_sz;

  char tc_str[2] = {tc, '\0'};
  PyObject *arr = PyObject_CallFunction(array_array, "s", tc_str);
  if (!arr) return NULL;

  // frombytes with aligned data.
  std::string aligned = data.substr(0, aligned_len);
  if (aligned.size() < (size_t)item_sz) {
    aligned.resize(item_sz, '\0');
  }
  PyRef pydata = PyBytes_FromStringAndSize(aligned.data(), aligned.size());
  if (!pydata) { Py_DECREF(arr); return NULL; }
  PyRef r = PyObject_CallMethod(arr, "frombytes", "O", (PyObject *)pydata);
  if (!r) { PyErr_Clear(); Py_DECREF(arr); return NULL; }
  return arr;
}

// ---------------------------------------------------------------------------
// Operations (9 ops).
// ---------------------------------------------------------------------------

// OP_ARRAY_FROMBYTES: FDP selects typecode, creates array from aligned fuzz
// data, then calls tobytes/tolist/reverse/byteswap. Exercises the array C
// module's core buffer and conversion operations.
static void op_array_frombytes(FuzzedDataProvider &fdp) {
  static const char kTypecodes[] = "bBHiIlLfdqQ";
  char tc = kTypecodes[fdp.ConsumeIntegralInRange<int>(0, 10)];
  std::string data = fdp.ConsumeBytesAsString(
      std::min(fdp.remaining_bytes(), (size_t)10000));

  PyRef arr(make_array(tc, data));
  CHECK(arr);

  {
    PyRef r = PyObject_CallMethod(arr, "tobytes", NULL);
    if (PyErr_Occurred()) PyErr_Clear();
  }
  {
    PyRef r = PyObject_CallMethod(arr, "tolist", NULL);
    if (PyErr_Occurred()) PyErr_Clear();
  }
  {
    PyRef r = PyObject_CallMethod(arr, "reverse", NULL);
    if (PyErr_Occurred()) PyErr_Clear();
  }
  {
    PyRef r = PyObject_CallMethod(arr, "byteswap", NULL);
    if (PyErr_Occurred()) PyErr_Clear();
  }
}

// OP_ARRAY_METHODS: FDP selects typecode, creates array, then exercises
// append/extend/pop/count/index/insert/remove/buffer_info/__sizeof__/
// __contains__/__iter__/len. Exercises the array C module's element ops.
static void op_array_methods(FuzzedDataProvider &fdp) {
  static const char kTypecodes[] = "bBHiIlLfdqQ";
  char tc = kTypecodes[fdp.ConsumeIntegralInRange<int>(0, 10)];
  std::string data = fdp.ConsumeBytesAsString(
      std::min(fdp.remaining_bytes(), (size_t)10000));

  PyRef arr(make_array(tc, data));
  CHECK(arr);

  // append(0)
  {
    PyRef zero = PyLong_FromLong(0);
    CHECK(zero);
    PyRef r = PyObject_CallMethod(arr, "append", "O", (PyObject *)zero);
    if (PyErr_Occurred()) PyErr_Clear();
  }

  // extend with a slice.
  {
    PyRef slice = PySequence_GetSlice(arr, 0, 1);
    if (slice) {
      PyRef r = PyObject_CallMethod(arr, "extend", "O", (PyObject *)slice);
      if (PyErr_Occurred()) PyErr_Clear();
    } else {
      PyErr_Clear();
    }
  }

  // pop()
  {
    PyRef r = PyObject_CallMethod(arr, "pop", NULL);
    if (PyErr_Occurred()) PyErr_Clear();
  }

  // count(first_element) and index(first_element)
  {
    PyRef first = PySequence_GetItem(arr, 0);
    if (first) {
      PyRef c = PyObject_CallMethod(arr, "count", "O", (PyObject *)first);
      if (PyErr_Occurred()) PyErr_Clear();
      PyRef idx = PyObject_CallMethod(arr, "index", "O", (PyObject *)first);
      if (PyErr_Occurred()) PyErr_Clear();
    } else {
      PyErr_Clear();
    }
  }

  // insert(0, 42) + remove(42)
  {
    PyRef val = PyLong_FromLong(42);
    CHECK(val);
    PyRef r = PyObject_CallMethod(arr, "insert", "iO", 0, (PyObject *)val);
    if (PyErr_Occurred()) PyErr_Clear();
    PyRef r2 = PyObject_CallMethod(arr, "remove", "O", (PyObject *)val);
    if (PyErr_Occurred()) PyErr_Clear();
  }

  // buffer_info, __sizeof__
  {
    PyRef bi = PyObject_CallMethod(arr, "buffer_info", NULL);
    if (PyErr_Occurred()) PyErr_Clear();
    PyRef sz = PyObject_CallMethod(arr, "__sizeof__", NULL);
    if (PyErr_Occurred()) PyErr_Clear();
  }

  // __contains__, iter, len
  {
    PyRef first = PySequence_GetItem(arr, 0);
    if (first) {
      int r = PySequence_Contains(arr, first);
      (void)r;
      if (PyErr_Occurred()) PyErr_Clear();
    } else {
      PyErr_Clear();
    }
    Py_ssize_t len = PyObject_Length(arr);
    (void)len;
    if (PyErr_Occurred()) PyErr_Clear();
  }
}

// OP_ARRAY_SLICE: FDP selects typecode, creates two arrays, does slice read,
// slice assignment, concatenation, repetition, comparison. Exercises the
// array C module's sequence protocol paths.
static void op_array_slice(FuzzedDataProvider &fdp) {
  static const char kTypecodes[] = "bBHiIlLfdqQ";
  char tc = kTypecodes[fdp.ConsumeIntegralInRange<int>(0, 10)];
  std::string data = fdp.ConsumeBytesAsString(
      std::min(fdp.remaining_bytes(), (size_t)10000));

  PyRef a1(make_array(tc, data));
  CHECK(a1);
  PyRef a2(make_array(tc, data));
  CHECK(a2);

  // Slice read a1[0:N].
  {
    Py_ssize_t len = PyObject_Length(a1);
    Py_ssize_t n = len < 4 ? len : 4;
    PyRef sl = PySequence_GetSlice(a1, 0, n);
    if (PyErr_Occurred()) PyErr_Clear();
  }

  // Slice assignment a1[::2] = array of zeros.
  {
    Py_ssize_t len = PyObject_Length(a1);
    if (len > 0) {
      // Count elements in a1[::2].
      Py_ssize_t slice_len = (len + 1) / 2;
      // Build array of zeros with same typecode.
      char tc_str[2] = {tc, '\0'};
      PyRef zeros_arr = PyObject_CallFunction(array_array, "s", tc_str);
      if (zeros_arr) {
        std::string zero_data(slice_len * typecode_itemsize(tc), '\0');
        PyRef pydata = PyBytes_FromStringAndSize(zero_data.data(),
                                                 zero_data.size());
        if (pydata) {
          PyRef fb = PyObject_CallMethod(zeros_arr, "frombytes", "O",
                                         (PyObject *)pydata);
          if (fb) {
            PyRef step = PyLong_FromLong(2);
            PyRef sl = PySlice_New(NULL, NULL, step);
            if (sl) {
              int r = PyObject_SetItem(a1, sl, zeros_arr);
              (void)r;
            }
          }
        }
      }
      if (PyErr_Occurred()) PyErr_Clear();
    }
  }

  // Concatenation a1 + a2.
  {
    PyRef r = PySequence_Concat(a1, a2);
    if (PyErr_Occurred()) PyErr_Clear();
  }

  // Repetition a1 * min(len, 3).
  {
    Py_ssize_t len = PyObject_Length(a1);
    int rep = len < 3 ? (int)len : 3;
    PyRef r = PySequence_Repeat(a1, rep);
    if (PyErr_Occurred()) PyErr_Clear();
  }

  // Comparison a1 == a2.
  {
    PyRef r = PyObject_RichCompare(a1, a2, Py_EQ);
    if (PyErr_Occurred()) PyErr_Clear();
  }
}

// OP_CTYPES: FDP selects sub-op for different ctypes from_buffer_copy calls.
// Exercises the _ctypes C module's buffer copy and array creation paths.
static void op_ctypes(FuzzedDataProvider &fdp) {
  int variant = fdp.ConsumeIntegralInRange<int>(0, 5);
  std::string data = fdp.ConsumeBytesAsString(
      std::min(fdp.remaining_bytes(), (size_t)10000));

  switch (variant) {
    case 0: {
      // c_char.from_buffer_copy(1 byte)
      std::string buf = data.substr(0, 1);
      if (buf.empty()) buf.push_back('\0');
      PyRef pydata = PyBytes_FromStringAndSize(buf.data(), buf.size());
      CHECK(pydata);
      PyRef r = PyObject_CallMethod(ct_c_char, "from_buffer_copy", "O",
                                    (PyObject *)pydata);
      break;
    }
    case 1: {
      // c_int.from_buffer_copy(4 bytes)
      std::string buf = data.substr(0, 4);
      buf.resize(4, '\0');
      PyRef pydata = PyBytes_FromStringAndSize(buf.data(), buf.size());
      CHECK(pydata);
      PyRef r = PyObject_CallMethod(ct_c_int, "from_buffer_copy", "O",
                                    (PyObject *)pydata);
      break;
    }
    case 2: {
      // c_double.from_buffer_copy(8 bytes)
      std::string buf = data.substr(0, 8);
      buf.resize(8, '\0');
      PyRef pydata = PyBytes_FromStringAndSize(buf.data(), buf.size());
      CHECK(pydata);
      PyRef r = PyObject_CallMethod(ct_c_double, "from_buffer_copy", "O",
                                    (PyObject *)pydata);
      break;
    }
    case 3: {
      // create_string_buffer(data[:256])
      std::string buf = data.substr(0, 256);
      PyRef pydata = PyBytes_FromStringAndSize(buf.data(), buf.size());
      CHECK(pydata);
      PyRef r = PyObject_CallFunction(ct_create_string_buffer, "O",
                                      (PyObject *)pydata);
      break;
    }
    case 4: {
      // (c_char * N).from_buffer_copy(data)
      if (data.empty()) break;
      PyRef n = PyLong_FromLong(data.size());
      CHECK(n);
      PyRef arr_type = PyNumber_Multiply(ct_c_char, n);
      CHECK(arr_type);
      PyRef pydata = PyBytes_FromStringAndSize(Y(data));
      CHECK(pydata);
      PyRef r = PyObject_CallMethod(arr_type, "from_buffer_copy", "O",
                                    (PyObject *)pydata);
      break;
    }
    case 5: {
      // Structure.from_buffer_copy(padded data)
      PyRef sz = PyObject_CallFunction(ct_sizeof, "O", ct_Structure_cls);
      CHECK(sz);
      long struct_sz = PyLong_AsLong(sz);
      std::string buf = data.substr(0, struct_sz);
      buf.resize(struct_sz, '\0');
      PyRef pydata = PyBytes_FromStringAndSize(buf.data(), buf.size());
      CHECK(pydata);
      PyRef r = PyObject_CallMethod(ct_Structure_cls, "from_buffer_copy", "O",
                                    (PyObject *)pydata);
      break;
    }
  }
  if (PyErr_Occurred()) PyErr_Clear();
}

// OP_MMAP: Create anonymous mmap, write data, then FDP selects actions.
// Exercises the mmap C module's core operations.
static void op_mmap(FuzzedDataProvider &fdp) {
  int action = fdp.ConsumeIntegralInRange<int>(0, 5);
  std::string data = fdp.ConsumeBytesAsString(
      std::min(fdp.remaining_bytes(), (size_t)10000));
  if (data.empty()) data.push_back('\0');

  // mmap(-1, size)
  Py_ssize_t map_size = data.size();
  PyRef mm = PyObject_CallFunction(mmap_mmap, "in", -1, map_size);
  CHECK(mm);

  // Write data.
  PyRef pydata = PyBytes_FromStringAndSize(Y(data));
  CHECK(pydata);
  {
    PyRef r = PyObject_CallMethod(mm, "write", "O", (PyObject *)pydata);
    if (!r) { PyErr_Clear(); goto cleanup; }
  }

  // Seek to 0.
  {
    PyRef r = PyObject_CallMethod(mm, "seek", "i", 0);
    if (!r) { PyErr_Clear(); goto cleanup; }
  }

  switch (action) {
    case 0: {
      // find + rfind
      size_t pat_len = data.size() < 4 ? data.size() : 4;
      PyRef pat = PyBytes_FromStringAndSize(data.data(), pat_len);
      CHECK(pat);
      {
        PyRef r = PyObject_CallMethod(mm, "find", "O", (PyObject *)pat);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        PyRef r = PyObject_CallMethod(mm, "rfind", "O", (PyObject *)pat);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      break;
    }
    case 1: {
      // read + readline
      {
        long n = map_size < 4 ? map_size : 4;
        PyRef r = PyObject_CallMethod(mm, "read", "l", n);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        PyRef sk = PyObject_CallMethod(mm, "seek", "i", 0);
        if (PyErr_Occurred()) PyErr_Clear();
        PyRef r = PyObject_CallMethod(mm, "readline", NULL);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      break;
    }
    case 2: {
      // resize + move
      long new_size = map_size * 2;
      if (new_size < 1) new_size = 1;
      {
        PyRef r = PyObject_CallMethod(mm, "resize", "l", new_size);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        long src = map_size < 2 ? 0 : 1;
        long count = map_size < 2 ? 0 : (map_size / 2 < new_size / 2 ?
                                          map_size / 2 : new_size / 2);
        PyRef r = PyObject_CallMethod(mm, "move", "lll",
                                      (long)0, src, count);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      break;
    }
    case 3: {
      // getitem + setitem
      {
        PyRef idx = PyLong_FromLong(0);
        CHECK(idx);
        PyRef r = PyObject_GetItem(mm, idx);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        Py_ssize_t n = map_size < 4 ? map_size : 4;
        PyRef sl = PySlice_New(PyLong_FromLong(0), PyLong_FromLong(n), NULL);
        CHECK(sl);
        PyRef r = PyObject_GetItem(mm, sl);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      if (data.size() > 0) {
        PyRef idx = PyLong_FromLong(0);
        CHECK(idx);
        PyRef val = PyLong_FromLong((unsigned char)data[0]);
        CHECK(val);
        PyObject_SetItem(mm, idx, val);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      break;
    }
    case 4: {
      // flush + size + tell
      {
        PyRef r = PyObject_CallMethod(mm, "flush", NULL);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        PyRef r = PyObject_CallMethod(mm, "size", NULL);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        PyRef r = PyObject_CallMethod(mm, "tell", NULL);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      break;
    }
    case 5: {
      // read all
      {
        PyRef r = PyObject_CallMethod(mm, "read", NULL);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      break;
    }
  }

cleanup:
  {
    PyRef r = PyObject_CallMethod(mm, "close", NULL);
    if (PyErr_Occurred()) PyErr_Clear();
  }
}

// OP_LOCALE: FDP selects strxfrm or strcoll. Exercises the _locale C module.
static void op_locale(FuzzedDataProvider &fdp) {
  int str_enc = fdp.ConsumeIntegralInRange<int>(0, 3);
  bool use_strcoll = fdp.ConsumeBool();
  std::string data = fdp.ConsumeBytesAsString(
      std::min(fdp.remaining_bytes(), (size_t)10000));
  PyRef pystr(fuzz_bytes_to_str(data, str_enc));
  CHECK(pystr);

  if (use_strcoll) {
    Py_ssize_t slen = PyUnicode_GET_LENGTH(pystr);
    Py_ssize_t mid = slen / 2;
    PyRef half1 = PyUnicode_Substring(pystr, 0, mid);
    CHECK(half1);
    PyRef half2 = PyUnicode_Substring(pystr, mid, slen);
    CHECK(half2);
    PyRef r = PyObject_CallFunction(locale_strcoll, "OO",
                                    (PyObject *)half1, (PyObject *)half2);
  } else {
    PyRef r = PyObject_CallFunction(locale_strxfrm, "O", (PyObject *)pystr);
  }
  if (PyErr_Occurred()) PyErr_Clear();
}

// OP_DBM: Open an in-memory dbm, write N key-value pairs, read back, iterate.
// Exercises the _dbm C extension module's storage operations.
static void op_dbm(FuzzedDataProvider &fdp) {
  std::string data = fdp.ConsumeBytesAsString(
      std::min(fdp.remaining_bytes(), (size_t)10000));

  // Use a unique filename based on the gc counter to avoid conflicts.
  char dbpath[64];
  snprintf(dbpath, sizeof(dbpath), "/tmp/_fuzz_dbm_%lu", gc_counter);

  PyRef db = PyObject_CallFunction(dbm_open, "ss", dbpath, "n");
  CHECK(db);

  // Write key-value pairs from fuzz data.
  size_t limit = data.size() < 64 ? data.size() : 64;
  for (size_t i = 0; i + 3 < limit; i += 4) {
    PyRef key = PyBytes_FromStringAndSize(data.data() + i, 2);
    if (!key) { PyErr_Clear(); continue; }
    PyRef val = PyBytes_FromStringAndSize(data.data() + i + 2, 2);
    if (!val) { PyErr_Clear(); continue; }
    int r = PyObject_SetItem(db, key, val);
    (void)r;
    if (PyErr_Occurred()) PyErr_Clear();
  }

  // Read keys.
  {
    PyRef keys = PyObject_CallMethod(db, "keys", NULL);
    if (keys) {
      PyRef it = PyObject_GetIter(keys);
      if (it) {
        PyObject *k;
        while ((k = PyIter_Next(it)) != NULL) {
          PyRef val = PyObject_GetItem(db, k);
          Py_DECREF(k);
          if (PyErr_Occurred()) PyErr_Clear();
        }
      }
    }
    if (PyErr_Occurred()) PyErr_Clear();
  }

  // Check membership.
  {
    PyRef test_key = PyBytes_FromStringAndSize("k", 1);
    if (test_key) {
      int r = PySequence_Contains(db, test_key);
      (void)r;
      if (PyErr_Occurred()) PyErr_Clear();
    }
  }

  // Close.
  {
    PyRef r = PyObject_CallMethod(db, "close", NULL);
    if (PyErr_Occurred()) PyErr_Clear();
  }
}

// Helper: Create a memory connection with PRAGMA max_page_count=100.
static PyObject *make_sqlite_conn() {
  PyObject *conn = PyObject_CallFunction(sqlite3_connect, "s", ":memory:");
  if (!conn) return NULL;
  PyRef r = PyObject_CallMethod(conn, "execute", "s",
                                "PRAGMA max_page_count=100");
  if (!r) {
    PyErr_Clear();
    Py_DECREF(conn);
    return NULL;
  }
  return conn;
}

// OP_SQLITE3_BASIC: connect(':memory:'), then FDP selects: execute fuzz SQL,
// parameterized queries, executemany, executescript, complete_statement.
// Exercises the _sqlite3 C module's basic execution paths.
static void op_sqlite3_basic(FuzzedDataProvider &fdp) {
  int str_enc = fdp.ConsumeIntegralInRange<int>(0, 3);
  int variant = fdp.ConsumeIntegralInRange<int>(0, 4);
  std::string data = fdp.ConsumeBytesAsString(
      std::min(fdp.remaining_bytes(), (size_t)10000));
  PyRef pystr(fuzz_bytes_to_str(data, str_enc));
  CHECK(pystr);

  PyRef conn(make_sqlite_conn());
  CHECK(conn);

  switch (variant) {
    case 0: {
      // Execute fuzz SQL.
      PyRef r = PyObject_CallMethod(conn, "execute", "O", (PyObject *)pystr);
      break;
    }
    case 1: {
      // Parameterized INSERT/SELECT/UPDATE/DELETE.
      PyRef pydata = PyBytes_FromStringAndSize(Y(data));
      CHECK(pydata);
      {
        PyRef r = PyObject_CallMethod(conn, "execute", "s",
                                      "CREATE TABLE t(a TEXT, b BLOB)");
        if (!r) { PyErr_Clear(); break; }
      }
      {
        PyRef params = PyTuple_Pack(2, (PyObject *)pystr, (PyObject *)pydata);
        CHECK(params);
        PyRef r = PyObject_CallMethod(conn, "execute", "sO",
                                      "INSERT INTO t VALUES(?, ?)",
                                      (PyObject *)params);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        // SELECT.
        PyRef sub = PyUnicode_Substring(pystr, 0, 32);
        if (!sub) { PyErr_Clear(); break; }
        PyRef params = PyTuple_Pack(1, (PyObject *)sub);
        CHECK(params);
        PyRef r = PyObject_CallMethod(conn, "execute", "sO",
                                      "SELECT * FROM t WHERE a LIKE ?",
                                      (PyObject *)params);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      break;
    }
    case 2: {
      // executemany.
      {
        PyRef r = PyObject_CallMethod(conn, "execute", "s",
                                      "CREATE TABLE t(v INTEGER)");
        if (!r) { PyErr_Clear(); break; }
      }
      {
        PyRef rows = PyList_New(0);
        CHECK(rows);
        size_t limit = data.size() < 64 ? data.size() : 64;
        for (size_t i = 0; i < limit; i++) {
          PyRef val = PyLong_FromLong((unsigned char)data[i]);
          PyRef tup = PyTuple_Pack(1, (PyObject *)val);
          if (tup) PyList_Append(rows, tup);
        }
        PyRef r = PyObject_CallMethod(conn, "executemany", "sO",
                                      "INSERT INTO t VALUES(?)",
                                      (PyObject *)rows);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        PyRef cur = PyObject_CallMethod(conn, "execute", "s",
            "SELECT count(*), sum(v), avg(v), min(v), max(v) FROM t");
        if (cur) {
          PyRef row = PyObject_CallMethod(cur, "fetchone", NULL);
          if (PyErr_Occurred()) PyErr_Clear();
        } else {
          PyErr_Clear();
        }
      }
      break;
    }
    case 3: {
      // executescript.
      Py_ssize_t slen = PyUnicode_GET_LENGTH(pystr);
      PyObject *sql = slen > 0 ? (PyObject *)pystr : NULL;
      if (!sql) {
        PyRef def = PyUnicode_FromString("SELECT 1;");
        PyRef r = PyObject_CallMethod(conn, "executescript", "O",
                                      (PyObject *)def);
      } else {
        PyRef r = PyObject_CallMethod(conn, "executescript", "O", sql);
      }
      break;
    }
    case 4: {
      // complete_statement.
      Py_ssize_t slen = PyUnicode_GET_LENGTH(pystr);
      PyObject *sql = slen > 0 ? (PyObject *)pystr : NULL;
      if (!sql) {
        PyRef def = PyUnicode_FromString("SELECT 1;");
        PyRef r = PyObject_CallFunction(sqlite3_complete_statement, "O",
                                        (PyObject *)def);
      } else {
        PyRef r = PyObject_CallFunction(sqlite3_complete_statement, "O", sql);
      }
      break;
    }
  }
  if (PyErr_Occurred()) PyErr_Clear();

  PyRef cl = PyObject_CallMethod(conn, "close", NULL);
  if (PyErr_Occurred()) PyErr_Clear();
}

// OP_SQLITE3_ADVANCED: connect(':memory:'), then FDP selects: create_function,
// create_aggregate, set_authorizer, create_collation, Row factory, blobopen,
// register_adapter. Exercises the _sqlite3 C module's advanced features.
static void op_sqlite3_advanced(FuzzedDataProvider &fdp) {
  int str_enc = fdp.ConsumeIntegralInRange<int>(0, 3);
  int variant = fdp.ConsumeIntegralInRange<int>(0, 6);
  std::string data = fdp.ConsumeBytesAsString(
      std::min(fdp.remaining_bytes(), (size_t)10000));
  PyRef pystr(fuzz_bytes_to_str(data, str_enc));
  CHECK(pystr);

  PyRef conn(make_sqlite_conn());
  CHECK(conn);

  switch (variant) {
    case 0: {
      // create_function + SELECT.
      PyRef globals = PyDict_New();
      CHECK(globals);
      PyDict_SetItemString(globals, "__builtins__", PyEval_GetBuiltins());
      PyRef fn = PyRun_String("lambda x: x", Py_eval_input, globals, globals);
      CHECK(fn);
      {
        PyRef r = PyObject_CallMethod(conn, "create_function", "siO",
                                      "fuzzfn", 1, (PyObject *)fn);
        if (!r) { PyErr_Clear(); break; }
      }
      {
        PyRef r = PyObject_CallMethod(conn, "execute", "s",
                                      "CREATE TABLE t(a TEXT)");
        if (!r) { PyErr_Clear(); break; }
      }
      {
        PyRef sub = PyUnicode_Substring(pystr, 0, 32);
        if (!sub) { PyErr_Clear(); break; }
        PyRef params = PyTuple_Pack(1, (PyObject *)sub);
        CHECK(params);
        PyRef r = PyObject_CallMethod(conn, "execute", "sO",
                                      "INSERT INTO t VALUES(?)",
                                      (PyObject *)params);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        PyRef cur = PyObject_CallMethod(conn, "execute", "s",
                                        "SELECT fuzzfn(a) FROM t");
        if (cur) {
          PyRef rows = PyObject_CallMethod(cur, "fetchall", NULL);
          if (PyErr_Occurred()) PyErr_Clear();
        } else {
          PyErr_Clear();
        }
      }
      break;
    }
    case 1: {
      // create_aggregate + SELECT.
      {
        PyRef r = PyObject_CallMethod(conn, "create_aggregate", "siO",
                                      "fuzzagg", 1,
                                      sqlite3_Aggregate_cls);
        if (!r) { PyErr_Clear(); break; }
      }
      {
        PyRef r = PyObject_CallMethod(conn, "execute", "s",
                                      "CREATE TABLE t(v INTEGER)");
        if (!r) { PyErr_Clear(); break; }
      }
      {
        PyRef rows = PyList_New(0);
        CHECK(rows);
        size_t limit = data.size() < 32 ? data.size() : 32;
        for (size_t i = 0; i < limit; i++) {
          PyRef val = PyLong_FromLong((unsigned char)data[i]);
          PyRef tup = PyTuple_Pack(1, (PyObject *)val);
          if (tup) PyList_Append(rows, tup);
        }
        PyRef r = PyObject_CallMethod(conn, "executemany", "sO",
                                      "INSERT INTO t VALUES(?)",
                                      (PyObject *)rows);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        PyRef cur = PyObject_CallMethod(conn, "execute", "s",
                                        "SELECT fuzzagg(v) FROM t");
        if (cur) {
          PyRef row = PyObject_CallMethod(cur, "fetchone", NULL);
          if (PyErr_Occurred()) PyErr_Clear();
        } else {
          PyErr_Clear();
        }
      }
      break;
    }
    case 2: {
      // set_authorizer + SELECT.
      PyRef globals = PyDict_New();
      CHECK(globals);
      PyDict_SetItemString(globals, "__builtins__", PyEval_GetBuiltins());
      PyRef code_str = PyUnicode_FromFormat(
          "lambda *a: %ld", sqlite3_SQLITE_OK_val);
      CHECK(code_str);
      PyRef auth_fn = PyRun_String(PyUnicode_AsUTF8(code_str),
                                   Py_eval_input, globals, globals);
      CHECK(auth_fn);
      {
        PyRef r = PyObject_CallMethod(conn, "set_authorizer", "O",
                                      (PyObject *)auth_fn);
        if (!r) { PyErr_Clear(); break; }
      }
      {
        PyRef r = PyObject_CallMethod(conn, "execute", "s",
                                      "CREATE TABLE t(a TEXT)");
        if (!r) { PyErr_Clear(); break; }
      }
      {
        PyRef sub = PyUnicode_Substring(pystr, 0, 16);
        if (!sub) { PyErr_Clear(); break; }
        PyRef params = PyTuple_Pack(1, (PyObject *)sub);
        CHECK(params);
        PyRef r = PyObject_CallMethod(conn, "execute", "sO",
                                      "INSERT INTO t VALUES(?)",
                                      (PyObject *)params);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        PyRef cur = PyObject_CallMethod(conn, "execute", "s",
                                        "SELECT * FROM t");
        if (cur) {
          PyRef rows = PyObject_CallMethod(cur, "fetchall", NULL);
          if (PyErr_Occurred()) PyErr_Clear();
        } else {
          PyErr_Clear();
        }
      }
      break;
    }
    case 3: {
      // create_collation + ORDER BY.
      PyRef globals = PyDict_New();
      CHECK(globals);
      PyDict_SetItemString(globals, "__builtins__", PyEval_GetBuiltins());
      PyRef coll_fn = PyRun_String(
          "lambda a, b: (a > b) - (a < b)",
          Py_eval_input, globals, globals);
      CHECK(coll_fn);
      {
        PyRef r = PyObject_CallMethod(conn, "create_collation", "sO",
                                      "fuzz", (PyObject *)coll_fn);
        if (!r) { PyErr_Clear(); break; }
      }
      {
        PyRef r = PyObject_CallMethod(conn, "execute", "s",
                                      "CREATE TABLE t(a TEXT)");
        if (!r) { PyErr_Clear(); break; }
      }
      {
        PyRef params = PyTuple_Pack(1, (PyObject *)pystr);
        CHECK(params);
        PyRef r = PyObject_CallMethod(conn, "execute", "sO",
                                      "INSERT INTO t VALUES(?)",
                                      (PyObject *)params);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        PyRef cur = PyObject_CallMethod(conn, "execute", "s",
            "SELECT * FROM t ORDER BY a COLLATE fuzz");
        if (cur) {
          PyRef rows = PyObject_CallMethod(cur, "fetchall", NULL);
          if (PyErr_Occurred()) PyErr_Clear();
        } else {
          PyErr_Clear();
        }
      }
      break;
    }
    case 4: {
      // Row factory + SELECT.
      PyObject_SetAttrString(conn, "row_factory", sqlite3_Row);
      {
        PyRef r = PyObject_CallMethod(conn, "execute", "s",
                                      "CREATE TABLE t(a TEXT, b INTEGER)");
        if (!r) { PyErr_Clear(); break; }
      }
      {
        PyRef sub = PyUnicode_Substring(pystr, 0, 8);
        if (!sub) { PyErr_Clear(); break; }
        PyRef params = PyTuple_Pack(2, (PyObject *)sub, PyLong_FromLong(42));
        CHECK(params);
        PyRef r = PyObject_CallMethod(conn, "execute", "sO",
                                      "INSERT INTO t VALUES(?, ?)",
                                      (PyObject *)params);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        PyRef cur = PyObject_CallMethod(conn, "execute", "s",
                                        "SELECT * FROM t");
        if (cur) {
          PyRef row = PyObject_CallMethod(cur, "fetchone", NULL);
          if (row && row.p != Py_None) {
            PyRef a = PyObject_GetItem(row, PyUnicode_FromString("a"));
            if (PyErr_Occurred()) PyErr_Clear();
            PyRef b = PyObject_GetItem(row, PyUnicode_FromString("b"));
            if (PyErr_Occurred()) PyErr_Clear();
            PyRef keys = PyObject_CallMethod(row, "keys", NULL);
            if (PyErr_Occurred()) PyErr_Clear();
          }
          if (PyErr_Occurred()) PyErr_Clear();
        } else {
          PyErr_Clear();
        }
      }
      break;
    }
    case 5: {
      // blobopen + read/write.
      {
        PyRef r = PyObject_CallMethod(conn, "execute", "s",
                                      "CREATE TABLE t(a BLOB)");
        if (!r) { PyErr_Clear(); break; }
      }
      {
        std::string blob_data = data.substr(0, 64);
        PyRef pydata = PyBytes_FromStringAndSize(blob_data.data(),
                                                 blob_data.size());
        CHECK(pydata);
        PyRef params = PyTuple_Pack(1, (PyObject *)pydata);
        CHECK(params);
        PyRef r = PyObject_CallMethod(conn, "execute", "sO",
                                      "INSERT INTO t VALUES(?)",
                                      (PyObject *)params);
        if (!r) { PyErr_Clear(); break; }
      }
      {
        PyRef cur = PyObject_CallMethod(conn, "execute", "s",
                                        "SELECT rowid FROM t");
        if (!cur) { PyErr_Clear(); break; }
        PyRef row = PyObject_CallMethod(cur, "fetchone", NULL);
        if (!row || row.p == Py_None) { PyErr_Clear(); break; }
        PyRef rid = PySequence_GetItem(row, 0);
        CHECK(rid);
        PyRef blob = PyObject_CallMethod(conn, "blobopen", "sssO",
                                         "main", "t", "a", (PyObject *)rid);
        if (!blob) { PyErr_Clear(); break; }
        {
          PyRef rd = PyObject_CallMethod(blob, "read", NULL);
          if (PyErr_Occurred()) PyErr_Clear();
        }
        {
          PyRef sk = PyObject_CallMethod(blob, "seek", "i", 0);
          if (PyErr_Occurred()) PyErr_Clear();
        }
        {
          size_t wr_len = data.size() < 64 ? data.size() : 64;
          PyRef wr_data = PyBytes_FromStringAndSize(data.data(), wr_len);
          if (wr_data) {
            PyRef wr = PyObject_CallMethod(blob, "write", "O",
                                           (PyObject *)wr_data);
            if (PyErr_Occurred()) PyErr_Clear();
          }
        }
        {
          PyRef cl = PyObject_CallMethod(blob, "close", NULL);
          if (PyErr_Occurred()) PyErr_Clear();
        }
      }
      break;
    }
    case 6: {
      // register_adapter.
      PyRef globals = PyDict_New();
      CHECK(globals);
      PyDict_SetItemString(globals, "__builtins__", PyEval_GetBuiltins());
      PyRef r = PyRun_String(
          "class _AdaptMe:\n"
          "    def __init__(self, v): self.v = v\n",
          Py_file_input, globals, globals);
      CHECK(r);
      PyRef adapt_cls = PyRef(PyDict_GetItemString(globals, "_AdaptMe"));
      Py_INCREF(adapt_cls.p);
      CHECK(adapt_cls);

      PyRef adapter_fn = PyRun_String(
          "lambda a: str(a.v)", Py_eval_input, globals, globals);
      CHECK(adapter_fn);

      {
        PyRef reg = PyObject_CallFunction(sqlite3_register_adapter, "OO",
                                          (PyObject *)adapt_cls,
                                          (PyObject *)adapter_fn);
        if (!reg) { PyErr_Clear(); break; }
      }
      {
        PyRef r2 = PyObject_CallMethod(conn, "execute", "s",
                                       "CREATE TABLE t(a TEXT)");
        if (!r2) { PyErr_Clear(); break; }
      }
      {
        PyRef sub = PyUnicode_Substring(pystr, 0, 8);
        if (!sub) { PyErr_Clear(); break; }
        PyRef obj = PyObject_CallFunction(adapt_cls, "O", (PyObject *)sub);
        if (!obj) { PyErr_Clear(); break; }
        PyRef params = PyTuple_Pack(1, (PyObject *)obj);
        CHECK(params);
        PyRef r3 = PyObject_CallMethod(conn, "execute", "sO",
                                       "INSERT INTO t VALUES(?)",
                                       (PyObject *)params);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      break;
    }
  }
  if (PyErr_Occurred()) PyErr_Clear();

  PyRef cl = PyObject_CallMethod(conn, "close", NULL);
  if (PyErr_Occurred()) PyErr_Clear();
}

// ---------------------------------------------------------------------------
// Dispatch.
// ---------------------------------------------------------------------------

enum Op {
  OP_ARRAY_FROMBYTES,
  OP_ARRAY_METHODS,
  OP_ARRAY_SLICE,
  OP_CTYPES,
  OP_MMAP,
  OP_LOCALE,
  OP_DBM,
  OP_SQLITE3_BASIC,
  OP_SQLITE3_ADVANCED,
  NUM_OPS
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  assert(Py_IsInitialized());
  init_dataops();
  if (size < 1 || size > 0x10000) return 0;
  if (PyErr_Occurred()) PyErr_Clear();

  FuzzedDataProvider fdp(data, size);
  switch (fdp.ConsumeIntegralInRange<int>(0, NUM_OPS - 1)) {
    case OP_ARRAY_FROMBYTES:
      op_array_frombytes(fdp);
      break;
    case OP_ARRAY_METHODS:
      op_array_methods(fdp);
      break;
    case OP_ARRAY_SLICE:
      op_array_slice(fdp);
      break;
    case OP_CTYPES:
      op_ctypes(fdp);
      break;
    case OP_MMAP:
      op_mmap(fdp);
      break;
    case OP_LOCALE:
      op_locale(fdp);
      break;
    case OP_DBM:
      op_dbm(fdp);
      break;
    case OP_SQLITE3_BASIC:
      op_sqlite3_basic(fdp);
      break;
    case OP_SQLITE3_ADVANCED:
      op_sqlite3_advanced(fdp);
      break;
  }

  if (++gc_counter % kGcInterval == 0) PyGC_Collect();
  return 0;
}
