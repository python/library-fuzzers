// fuzz_pickle.cpp — Fuzzer for CPython's pickle C extension module.
//
// This fuzzer exercises the following CPython C extension module via
// its Python API, called through the Python C API from C++:
//
//   _pickle             — pickle.dumps() with 8 container types (bytes, str,
//                         list, tuple, set, frozenset, bytearray, dict) across
//                         protocols 0-5 and fix_imports flag.
//                         pickle.loads() via RestrictedUnpickler (blocks
//                         find_class), PersistentUnpickler (handles PERSID/
//                         BINPERSID), and RestrictedUnpickler with
//                         encoding='bytes'.
//                         Pickler chain: dump, clear_memo, dump, getvalue.
//                         Round-trip: dumps then loads.
//
// FDP selects one of 4 operation types. Each operation consumes further
// bytes via FuzzedDataProvider to parameterize the call (protocol number,
// container type, boolean flags).
//
// All module functions are imported once during init and cached as static
// PyObject* pointers. Two pickle Unpickler subclasses (RestrictedUnpickler,
// PersistentUnpickler) are defined via PyRun_String at init time.
// PyRef (RAII) prevents reference leaks. Max input size: 1 MB.

#include "fuzz_helpers.h"

static PyObject *pickle_dumps, *pickle_loads;
static PyObject *pickle_Pickler;
static PyObject *bytesio_ctor;
static PyObject *RestrictedUnpickler_cls, *PersistentUnpickler_cls;

static int initialized = 0;

static void init_pickle(void) {
  if (initialized) return;

  pickle_dumps = import_attr("pickle", "dumps");
  pickle_loads = import_attr("pickle", "loads");
  pickle_Pickler = import_attr("pickle", "Pickler");
  bytesio_ctor = import_attr("io", "BytesIO");
  static const char *kPickleHelpers =
      "import pickle, io\n"
      "class RestrictedUnpickler(pickle.Unpickler):\n"
      "    def find_class(self, module, name):\n"
      "        raise pickle.UnpicklingError('restricted')\n"
      "class PersistentUnpickler(pickle.Unpickler):\n"
      "    def persistent_load(self, pid): return pid\n"
      "    def find_class(self, module, name):\n"
      "        raise pickle.UnpicklingError('restricted')\n";
  RestrictedUnpickler_cls = run_python_and_get(kPickleHelpers,
                                               "RestrictedUnpickler");
  PersistentUnpickler_cls = run_python_and_get(kPickleHelpers,
                                               "PersistentUnpickler");

  assert(!PyErr_Occurred());
  initialized = 1;
}

// Container types for build_pickle_container.
enum ContainerType {
  CT_RAW_BYTES, CT_STR, CT_LIST, CT_TUPLE,
  CT_SET, CT_FROZENSET, CT_BYTEARRAY, CT_DICT,
  NUM_CONTAINER_TYPES
};

// Hashable types that can be used as dict keys.
// list, set, bytearray, and dict are unhashable.
enum HashableType {
  HT_RAW_BYTES, HT_STR, HT_INT, HT_FLOAT, HT_TUPLE, HT_FROZENSET,
  NUM_HASHABLE_TYPES
};

// Build a single hashable Python value from fdp, suitable for dict keys.
static PyObject *build_hashable_value(FuzzedDataProvider &fdp) {
  int t = fdp.ConsumeIntegralInRange<int>(0, NUM_HASHABLE_TYPES - 1);
  switch (t) {
    case HT_RAW_BYTES: {
      size_t len = fdp.ConsumeIntegralInRange<size_t>(
          0, std::min(fdp.remaining_bytes(), (size_t)10000));
      std::string s = fdp.ConsumeBytesAsString(len);
      return PyBytes_FromStringAndSize(Y(s));
    }
    case HT_STR: {
      int str_enc = fdp.ConsumeIntegralInRange<int>(0, 3);
      size_t len = fdp.ConsumeIntegralInRange<size_t>(
          0, std::min(fdp.remaining_bytes(), (size_t)10000));
      std::string s = fdp.ConsumeBytesAsString(len);
      return fuzz_bytes_to_str(s, str_enc);
    }
    case HT_INT: {
      long v = fdp.ConsumeIntegral<int32_t>();
      return PyLong_FromLong(v);
    }
    case HT_FLOAT: {
      double v = fdp.ConsumeFloatingPoint<double>();
      return PyFloat_FromDouble(v);
    }
    case HT_TUPLE: {
      size_t n = fdp.ConsumeIntegralInRange<size_t>(0, 200);
      PyObject *tup = PyTuple_New((Py_ssize_t)n);
      if (!tup) return NULL;
      for (size_t i = 0; i < n; i++) {
        long v = fdp.ConsumeIntegral<int32_t>();
        PyObject *item = PyLong_FromLong(v);
        if (!item) { Py_DECREF(tup); return NULL; }
        PyTuple_SET_ITEM(tup, i, item);
      }
      return tup;
    }
    case HT_FROZENSET: {
      size_t n = fdp.ConsumeIntegralInRange<size_t>(0, 200);
      PyObject *lst = PyList_New((Py_ssize_t)n);
      if (!lst) return NULL;
      for (size_t i = 0; i < n; i++) {
        long v = fdp.ConsumeIntegral<int32_t>();
        PyObject *item = PyLong_FromLong(v);
        if (!item) { Py_DECREF(lst); return NULL; }
        PyList_SET_ITEM(lst, i, item);
      }
      PyObject *fs = PyFrozenSet_New(lst);
      Py_DECREF(lst);
      return fs;
    }
    default:
      return PyLong_FromLong(0);
  }
}

// Value types for dict values (any picklable type, no recursion into dict).
enum ValueType {
  VT_RAW_BYTES, VT_STR, VT_INT, VT_FLOAT, VT_LIST, VT_TUPLE,
  VT_SET, VT_FROZENSET, VT_BYTEARRAY, VT_NONE,
  NUM_VALUE_TYPES
};

// Build a single Python value from fdp, suitable for dict values.
static PyObject *build_any_value(FuzzedDataProvider &fdp) {
  int t = fdp.ConsumeIntegralInRange<int>(0, NUM_VALUE_TYPES - 1);
  switch (t) {
    case VT_RAW_BYTES: {
      size_t len = fdp.ConsumeIntegralInRange<size_t>(
          0, std::min(fdp.remaining_bytes(), (size_t)10000));
      std::string s = fdp.ConsumeBytesAsString(len);
      return PyBytes_FromStringAndSize(Y(s));
    }
    case VT_STR: {
      int str_enc = fdp.ConsumeIntegralInRange<int>(0, 3);
      size_t len = fdp.ConsumeIntegralInRange<size_t>(
          0, std::min(fdp.remaining_bytes(), (size_t)10000));
      std::string s = fdp.ConsumeBytesAsString(len);
      return fuzz_bytes_to_str(s, str_enc);
    }
    case VT_INT: {
      long v = fdp.ConsumeIntegral<int32_t>();
      return PyLong_FromLong(v);
    }
    case VT_FLOAT: {
      double v = fdp.ConsumeFloatingPoint<double>();
      return PyFloat_FromDouble(v);
    }
    case VT_LIST: {
      size_t n = fdp.ConsumeIntegralInRange<size_t>(0, 200);
      PyObject *lst = PyList_New((Py_ssize_t)n);
      if (!lst) return NULL;
      for (size_t i = 0; i < n; i++) {
        long v = fdp.ConsumeIntegral<int32_t>();
        PyObject *item = PyLong_FromLong(v);
        if (!item) { Py_DECREF(lst); return NULL; }
        PyList_SET_ITEM(lst, i, item);
      }
      return lst;
    }
    case VT_TUPLE: {
      size_t n = fdp.ConsumeIntegralInRange<size_t>(0, 200);
      PyObject *tup = PyTuple_New((Py_ssize_t)n);
      if (!tup) return NULL;
      for (size_t i = 0; i < n; i++) {
        long v = fdp.ConsumeIntegral<int32_t>();
        PyObject *item = PyLong_FromLong(v);
        if (!item) { Py_DECREF(tup); return NULL; }
        PyTuple_SET_ITEM(tup, i, item);
      }
      return tup;
    }
    case VT_SET: {
      size_t n = fdp.ConsumeIntegralInRange<size_t>(0, 200);
      PyObject *lst = PyList_New((Py_ssize_t)n);
      if (!lst) return NULL;
      for (size_t i = 0; i < n; i++) {
        long v = fdp.ConsumeIntegral<int32_t>();
        PyObject *item = PyLong_FromLong(v);
        if (!item) { Py_DECREF(lst); return NULL; }
        PyList_SET_ITEM(lst, i, item);
      }
      PyObject *s = PySet_New(lst);
      Py_DECREF(lst);
      return s;
    }
    case VT_FROZENSET: {
      size_t n = fdp.ConsumeIntegralInRange<size_t>(0, 200);
      PyObject *lst = PyList_New((Py_ssize_t)n);
      if (!lst) return NULL;
      for (size_t i = 0; i < n; i++) {
        long v = fdp.ConsumeIntegral<int32_t>();
        PyObject *item = PyLong_FromLong(v);
        if (!item) { Py_DECREF(lst); return NULL; }
        PyList_SET_ITEM(lst, i, item);
      }
      PyObject *fs = PyFrozenSet_New(lst);
      Py_DECREF(lst);
      return fs;
    }
    case VT_BYTEARRAY: {
      size_t len = fdp.ConsumeIntegralInRange<size_t>(
          0, std::min(fdp.remaining_bytes(), (size_t)10000));
      std::string s = fdp.ConsumeBytesAsString(len);
      return PyByteArray_FromStringAndSize(Y(s));
    }
    case VT_NONE:
      Py_INCREF(Py_None);
      return Py_None;
    default:
      Py_INCREF(Py_None);
      return Py_None;
  }
}

// Build a Python container from fuzz bytes for pickle.dumps operations.
// Capped at 10000 elements to keep serialization fast.
// str_enc selects the byte-to-str decoding (see fuzz_bytes_to_str).
// For CT_DICT, keys and values are consumed directly from fdp.
static PyObject *build_pickle_container(FuzzedDataProvider &fdp,
                                        int type, const uint8_t *buf,
                                        size_t len, int str_enc) {
  if (len > 10000) len = 10000;
  switch (type) {
    case CT_RAW_BYTES:
      return PyBytes_FromStringAndSize((const char *)buf, len);
    case CT_STR: {
      std::string s((const char *)buf, len);
      return fuzz_bytes_to_str(s, str_enc);
    }
    case CT_LIST: {
      PyObject *lst = PyList_New((Py_ssize_t)len);
      if (!lst) return NULL;
      for (size_t i = 0; i < len; i++) {
        PyObject *v = PyLong_FromLong(buf[i]);
        if (!v) { Py_DECREF(lst); return NULL; }
        PyList_SET_ITEM(lst, i, v);
      }
      return lst;
    }
    case CT_TUPLE: {
      PyObject *tup = PyTuple_New((Py_ssize_t)len);
      if (!tup) return NULL;
      for (size_t i = 0; i < len; i++) {
        PyObject *v = PyLong_FromLong(buf[i]);
        if (!v) { Py_DECREF(tup); return NULL; }
        PyTuple_SET_ITEM(tup, i, v);
      }
      return tup;
    }
    case CT_SET: {
      PyObject *lst = PyList_New((Py_ssize_t)len);
      if (!lst) return NULL;
      for (size_t i = 0; i < len; i++) {
        PyObject *v = PyLong_FromLong(buf[i]);
        if (!v) { Py_DECREF(lst); return NULL; }
        PyList_SET_ITEM(lst, i, v);
      }
      PyObject *s = PySet_New(lst);
      Py_DECREF(lst);
      return s;
    }
    case CT_FROZENSET: {
      PyObject *lst = PyList_New((Py_ssize_t)len);
      if (!lst) return NULL;
      for (size_t i = 0; i < len; i++) {
        PyObject *v = PyLong_FromLong(buf[i]);
        if (!v) { Py_DECREF(lst); return NULL; }
        PyList_SET_ITEM(lst, i, v);
      }
      PyObject *s = PyFrozenSet_New(lst);
      Py_DECREF(lst);
      return s;
    }
    case CT_BYTEARRAY:
      return PyByteArray_FromStringAndSize((const char *)buf, len);
    case CT_DICT: {
      // Build a dict with fuzzer-chosen types for each key and value.
      // Keys use hashable types only; values can be any picklable type.
      size_t n_entries = fdp.ConsumeIntegralInRange<size_t>(0, 64);
      PyObject *d = PyDict_New();
      if (!d) return NULL;
      for (size_t i = 0; i < n_entries && fdp.remaining_bytes() > 0; i++) {
        PyRef key(build_hashable_value(fdp));
        if (!key) { Py_DECREF(d); return NULL; }
        PyRef val(build_any_value(fdp));
        if (!val) { Py_DECREF(d); return NULL; }
        PyDict_SetItem(d, key, val);
      }
      return d;
    }
    default:
      return PyBytes_FromStringAndSize((const char *)buf, len);
  }
}

// ---------------------------------------------------------------------------
// Operations (4 ops)
// ---------------------------------------------------------------------------

// OP_PICKLE_DUMPS: Build a fuzz-chosen container type, then call
// pickle.dumps(obj, protocol=N, fix_imports=bool). Protocol is fuzz-chosen
// 0-5, exercising all pickle opcodes.
static void op_pickle_dumps(FuzzedDataProvider &fdp) {
  int container_type = fdp.ConsumeIntegralInRange<int>(0, NUM_CONTAINER_TYPES - 1);
  int protocol = fdp.ConsumeIntegralInRange<int>(0, 5);
  bool fix_imports = fdp.ConsumeBool();
  int str_enc = fdp.ConsumeIntegralInRange<int>(0, 3);
  if (fdp.remaining_bytes() == 0) return;
  size_t data_len = fdp.ConsumeIntegralInRange<size_t>(
      1, std::min(fdp.remaining_bytes(), (size_t)10000));
  std::string data = fdp.ConsumeBytesAsString(data_len);

  PyRef obj(build_pickle_container(
      fdp, container_type, (const uint8_t *)data.data(), data.size(), str_enc));
  CHECK(obj);

  PyRef kwargs = PyDict_New();
  CHECK(kwargs);
  PyRef proto = PyLong_FromLong(protocol);
  CHECK(proto);
  PyDict_SetItemString(kwargs, "protocol", proto);
  PyDict_SetItemString(kwargs, "fix_imports",
                       fix_imports ? Py_True : Py_False);
  PyRef args = PyTuple_Pack(1, (PyObject *)obj);
  CHECK(args);
  PyRef r = PyObject_Call(pickle_dumps, args, kwargs);
  if (PyErr_Occurred()) PyErr_Clear();
}

// OP_PICKLE_LOADS: Wrap fuzz data in BytesIO, then unpickle via one of 3
// Unpickler subclass variants (fuzz-chosen).
static void op_pickle_loads(FuzzedDataProvider &fdp) {
  int variant = fdp.ConsumeIntegralInRange<int>(0, 2);
  std::string data = fdp.ConsumeRemainingBytesAsString();
  PyRef pydata = PyBytes_FromStringAndSize(Y(data));
  CHECK(pydata);
  PyRef bio = PyObject_CallFunction(bytesio_ctor, "O",
                                    (PyObject *)pydata);
  CHECK(bio);

  PyObject *cls = nullptr;
  PyRef kwargs_ref;
  switch (variant) {
    case 0:
      cls = RestrictedUnpickler_cls;
      break;
    case 1:
      cls = PersistentUnpickler_cls;
      break;
    case 2: {
      cls = RestrictedUnpickler_cls;
      kwargs_ref = PyRef(PyDict_New());
      CHECK(kwargs_ref);
      PyDict_SetItemString(kwargs_ref, "fix_imports", Py_True);
      PyRef enc = PyUnicode_FromString("bytes");
      CHECK(enc);
      PyDict_SetItemString(kwargs_ref, "encoding", enc);
      break;
    }
  }

  PyRef args = PyTuple_Pack(1, (PyObject *)bio);
  CHECK(args);
  PyRef unpickler = PyObject_Call(
      cls, args, kwargs_ref.p ? (PyObject *)kwargs_ref : NULL);
  CHECK(unpickler);
  PyRef r = PyObject_CallMethod(unpickler, "load", NULL);
  if (PyErr_Occurred()) PyErr_Clear();
}

// OP_PICKLE_PICKLER: Create pickle.Pickler(BytesIO, protocol=N), then chain:
// .dump(list_of_ints), .clear_memo(), .dump(str), .getvalue().
static void op_pickle_pickler(FuzzedDataProvider &fdp) {
  int protocol = fdp.ConsumeIntegralInRange<int>(0, 5);
  int str_enc = fdp.ConsumeIntegralInRange<int>(0, 3);
  if (fdp.remaining_bytes() == 0) return;
  size_t data_len = fdp.ConsumeIntegralInRange<size_t>(
      1, std::min(fdp.remaining_bytes(), (size_t)10000));
  std::string data = fdp.ConsumeBytesAsString(data_len);
  std::string data2 = fdp.ConsumeRemainingBytesAsString();

  // Create an in-memory BytesIO buffer for the Pickler to write into.
  PyRef bio = PyObject_CallFunction(bytesio_ctor, NULL);
  CHECK(bio);

  // Construct a Pickler targeting the buffer with a fuzz-chosen protocol
  // (0-5). Different protocols use different opcodes internally.
  PyRef pickler = PyObject_CallFunction(pickle_Pickler, "Oi",
                                        (PyObject *)bio, protocol);
  CHECK(pickler);

  // Build a list-of-ints container from the first fuzz string and dump it.
  // Exercises the Pickler's serialization of sequences.
  PyRef obj1(build_pickle_container(
      fdp, CT_LIST, (const uint8_t *)data.data(), data.size(), str_enc));
  CHECK(obj1);

  PyRef r1 = PyObject_CallMethod(pickler, "dump", "O", (PyObject *)obj1);
  if (!r1) {
    PyErr_Clear();
    return;
  }

  // Clear the memo table between dumps. Exercises the memo-reset path
  // so the second dump re-encodes objects from scratch.
  PyRef cm = PyObject_CallMethod(pickler, "clear_memo", NULL);
  if (PyErr_Occurred()) PyErr_Clear();

  // Build a str from a second independent fuzz string and dump it.
  // Exercises string serialization after a memo clear, using a different
  // object type than the first dump.
  PyRef obj2(fuzz_bytes_to_str(data2, str_enc));
  CHECK(obj2);
  PyRef r2 = PyObject_CallMethod(pickler, "dump", "O", (PyObject *)obj2);
  if (PyErr_Occurred()) PyErr_Clear();

  // Retrieve the full serialized output from the BytesIO buffer.
  // Exercises the buffer-readback path after multiple dumps.
  PyRef val = PyObject_CallMethod(bio, "getvalue", NULL);
  if (PyErr_Occurred()) PyErr_Clear();
}

// OP_PICKLE_ROUNDTRIP: Build a fuzz-chosen container, pickle.dumps() it,
// then pickle.loads() the result.
static void op_pickle_roundtrip(FuzzedDataProvider &fdp) {
  int container_type = fdp.ConsumeIntegralInRange<int>(0, NUM_CONTAINER_TYPES - 1);
  int str_enc = fdp.ConsumeIntegralInRange<int>(0, 3);
  if (fdp.remaining_bytes() == 0) return;
  size_t data_len = fdp.ConsumeIntegralInRange<size_t>(
      1, std::min(fdp.remaining_bytes(), (size_t)10000));
  std::string data = fdp.ConsumeBytesAsString(data_len);

  PyRef obj(build_pickle_container(
      fdp, container_type, (const uint8_t *)data.data(), data.size(), str_enc));
  CHECK(obj);

  PyRef dumped = PyObject_CallFunction(pickle_dumps, "O", (PyObject *)obj);
  if (!dumped) {
    PyErr_Clear();
    return;
  }
  PyRef loaded = PyObject_CallFunction(pickle_loads, "O",
                                       (PyObject *)dumped);
  if (PyErr_Occurred()) PyErr_Clear();
}

enum Op {
  OP_PICKLE_DUMPS,
  OP_PICKLE_LOADS,
  OP_PICKLE_PICKLER,
  OP_PICKLE_ROUNDTRIP,
  NUM_OPS
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  assert(Py_IsInitialized());
  init_pickle();
  if (size < 1 || size > kMaxInputSize) return 0;
  if (PyErr_Occurred()) PyErr_Clear();

  FuzzedDataProvider fdp(data, size);
  switch (fdp.ConsumeIntegralInRange<int>(0, NUM_OPS - 1)) {
    case OP_PICKLE_DUMPS:
      op_pickle_dumps(fdp);
      break;
    case OP_PICKLE_LOADS:
      op_pickle_loads(fdp);
      break;
    case OP_PICKLE_PICKLER:
      op_pickle_pickler(fdp);
      break;
    case OP_PICKLE_ROUNDTRIP:
      op_pickle_roundtrip(fdp);
      break;
  }

  return 0;
}
