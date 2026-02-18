// fuzz_textops.cpp — Fuzzer for CPython's text-processing C extension modules.
//
// This fuzzer exercises the following CPython C extension modules via
// their Python API, called through the Python C API from C++:
//
//   datetime             — date/time/datetime.fromisoformat(), strptime(),
//                          strftime(), format()
//   collections          — _count_elements (Counter internals)
//   unicodedata          — category, bidirectional, numeric, decimal,
//                          combining, east_asian_width, mirrored, name,
//                          decomposition, normalize, is_normalized, lookup,
//                          ucd_3_2_0.normalize
//   _io (StringIO)       — write, seek, read, getvalue, readline, readlines,
//                          truncate, iteration
//
// The first byte of fuzz input selects one of 6 operation types. Each
// operation consumes further bytes via FuzzedDataProvider to parameterize
// the call (format selection, character range, normalization form).
//
// All module functions and class constructors are imported once during init
// and cached as static PyObject* pointers. PyRef (RAII) prevents reference
// leaks. PyGC_Collect() runs every 200 iterations. Max input size: 64 KB.

#include "fuzz_helpers.h"

// ---------------------------------------------------------------------------
// Cached module objects, initialized once.
// ---------------------------------------------------------------------------

// datetime
static PyObject *dt_date, *dt_time, *dt_datetime;

// collections
static PyObject *collections_count_elements;

// unicodedata
static PyObject *ud_category, *ud_bidirectional, *ud_normalize, *ud_numeric;
static PyObject *ud_lookup, *ud_name, *ud_decomposition, *ud_is_normalized;
static PyObject *ud_east_asian_width, *ud_mirrored, *ud_decimal, *ud_combining;
static PyObject *ud_ucd_3_2_0;

// io
static PyObject *stringio_ctor;

// struct
static PyObject *struct_unpack;

static unsigned long gc_counter = 0;

static int initialized = 0;

static void init_textops(void) {
  if (initialized) return;

  // datetime
  dt_date = import_attr("datetime", "date");
  dt_time = import_attr("datetime", "time");
  dt_datetime = import_attr("datetime", "datetime");

  // collections
  collections_count_elements = import_attr("collections", "_count_elements");

  // unicodedata
  ud_category = import_attr("unicodedata", "category");
  ud_bidirectional = import_attr("unicodedata", "bidirectional");
  ud_normalize = import_attr("unicodedata", "normalize");
  ud_numeric = import_attr("unicodedata", "numeric");
  ud_lookup = import_attr("unicodedata", "lookup");
  ud_name = import_attr("unicodedata", "name");
  ud_decomposition = import_attr("unicodedata", "decomposition");
  ud_is_normalized = import_attr("unicodedata", "is_normalized");
  ud_east_asian_width = import_attr("unicodedata", "east_asian_width");
  ud_mirrored = import_attr("unicodedata", "mirrored");
  ud_decimal = import_attr("unicodedata", "decimal");
  ud_combining = import_attr("unicodedata", "combining");
  ud_ucd_3_2_0 = import_attr("unicodedata", "ucd_3_2_0");

  // io
  stringio_ctor = import_attr("io", "StringIO");

  // struct
  struct_unpack = import_attr("struct", "unpack");

  // Suppress warnings.
  PyRun_SimpleString("import warnings; warnings.filterwarnings('ignore')");

  assert(!PyErr_Occurred());
  initialized = 1;
}

// ---------------------------------------------------------------------------
// Operations (6 ops).
// ---------------------------------------------------------------------------

// OP_DATETIME_PARSE: FDP selects variant — date/time/datetime.fromisoformat()
// or datetime.strptime() with a fuzz-chosen format string. Exercises the
// datetime C module's parsing paths.
static void op_datetime_parse(FuzzedDataProvider &fdp) {
  int str_enc = fdp.ConsumeIntegralInRange<int>(0, 3);
  int variant = fdp.ConsumeIntegralInRange<int>(0, 4);
  std::string data = fdp.ConsumeBytesAsString(
      std::min(fdp.remaining_bytes(), (size_t)10000));
  PyRef pystr(fuzz_bytes_to_str(data, str_enc));
  CHECK(pystr);

  switch (variant) {
    case 0: {
      PyRef r = PyObject_CallMethod(dt_date, "fromisoformat", "O",
                                    (PyObject *)pystr);
      break;
    }
    case 1: {
      PyRef r = PyObject_CallMethod(dt_time, "fromisoformat", "O",
                                    (PyObject *)pystr);
      break;
    }
    case 2: {
      PyRef r = PyObject_CallMethod(dt_datetime, "fromisoformat", "O",
                                    (PyObject *)pystr);
      break;
    }
    case 3: {
      PyRef fmt = PyUnicode_FromString("%Y-%m-%d %H:%M:%S");
      CHECK(fmt);
      PyRef r = PyObject_CallMethod(dt_datetime, "strptime", "OO",
                                    (PyObject *)pystr, (PyObject *)fmt);
      break;
    }
    case 4: {
      PyRef fmt = PyUnicode_FromString("%Y/%m/%dT%H:%M");
      CHECK(fmt);
      PyRef r = PyObject_CallMethod(dt_datetime, "strptime", "OO",
                                    (PyObject *)pystr, (PyObject *)fmt);
      break;
    }
  }
  if (PyErr_Occurred()) PyErr_Clear();
}

// OP_DATETIME_FORMAT: Unpack 6 shorts from first 12 bytes to build a valid
// datetime, then call strftime() with the remaining fuzz data as the format
// string. Exercises datetime formatting code paths.
static void op_datetime_format(FuzzedDataProvider &fdp) {
  // Need at least 12 bytes for the datetime fields.
  std::string header = fdp.ConsumeBytesAsString(12);
  if (header.size() < 12) return;

  int str_enc = fdp.ConsumeIntegralInRange<int>(0, 3);
  std::string fmt_data = fdp.ConsumeBytesAsString(
      std::min(fdp.remaining_bytes(), (size_t)10000));
  PyRef fmt_str(fuzz_bytes_to_str(fmt_data, str_enc));
  CHECK(fmt_str);

  // Unpack 6 unsigned shorts via struct.unpack.
  PyRef hdr_bytes = PyBytes_FromStringAndSize(header.data(), 12);
  CHECK(hdr_bytes);
  PyRef vals = PyObject_CallFunction(struct_unpack, "sO", "6H",
                                     (PyObject *)hdr_bytes);
  CHECK(vals);

  // Extract fields and clamp to valid ranges.
  long v[6];
  for (int i = 0; i < 6; i++) {
    PyObject *item = PyTuple_GetItem(vals, i);
    v[i] = PyLong_AsLong(item);
  }
  long year = (v[0] % 9999) + 1;
  long month = (v[1] % 12) + 1;
  long day = (v[2] % 28) + 1;
  long hour = v[3] % 24;
  long minute = v[4] % 60;
  long second = v[5] % 60;

  PyRef dt = PyObject_CallFunction(dt_datetime, "llllll",
                                   year, month, day, hour, minute, second);
  CHECK(dt);

  // strftime on datetime.
  {
    PyRef r = PyObject_CallMethod(dt, "strftime", "O", (PyObject *)fmt_str);
    if (PyErr_Occurred()) PyErr_Clear();
  }

  // strftime on date.
  {
    PyRef date_obj = PyObject_CallMethod(dt, "date", NULL);
    if (date_obj) {
      PyRef r = PyObject_CallMethod(date_obj, "strftime", "O",
                                    (PyObject *)fmt_str);
      if (PyErr_Occurred()) PyErr_Clear();
    } else {
      PyErr_Clear();
    }
  }

  // strftime on time.
  {
    PyRef time_obj = PyObject_CallMethod(dt, "time", NULL);
    if (time_obj) {
      PyRef r = PyObject_CallMethod(time_obj, "strftime", "O",
                                    (PyObject *)fmt_str);
      if (PyErr_Occurred()) PyErr_Clear();
    } else {
      PyErr_Clear();
    }
  }

  // format(date, str[:16]).
  {
    PyRef date_obj = PyObject_CallMethod(dt, "date", NULL);
    if (date_obj) {
      // Cap format spec to 16 chars.
      Py_ssize_t flen = PyUnicode_GET_LENGTH(fmt_str);
      PyRef short_fmt = PyUnicode_Substring(fmt_str, 0,
                                            flen < 16 ? flen : 16);
      if (short_fmt) {
        PyRef r = PyObject_Format(date_obj, short_fmt);
        if (PyErr_Occurred()) PyErr_Clear();
      } else {
        PyErr_Clear();
      }
    } else {
      PyErr_Clear();
    }
  }
}

// OP_COLLECTIONS_COUNT: Build a dict and call collections._count_elements()
// with a fuzz-generated string. Exercises the Counter internals C path.
static void op_collections_count(FuzzedDataProvider &fdp) {
  int str_enc = fdp.ConsumeIntegralInRange<int>(0, 3);
  std::string data = fdp.ConsumeBytesAsString(
      std::min(fdp.remaining_bytes(), (size_t)10000));
  PyRef pystr(fuzz_bytes_to_str(data, str_enc));
  CHECK(pystr);

  PyRef d = PyDict_New();
  CHECK(d);
  PyRef r = PyObject_CallFunction(collections_count_elements, "OO",
                                  (PyObject *)d, (PyObject *)pystr);
  if (PyErr_Occurred()) PyErr_Clear();
}

// OP_UNICODEDATA_CHARINFO: Convert data to str (cap 200 chars), then call
// per-character unicodedata functions. FDP selects which functions to call.
// Exercises the unicodedata C module character-info paths.
static void op_unicodedata_charinfo(FuzzedDataProvider &fdp) {
  int str_enc = fdp.ConsumeIntegralInRange<int>(0, 3);
  uint8_t func_mask = fdp.ConsumeIntegral<uint8_t>();
  std::string data = fdp.ConsumeBytesAsString(
      std::min(fdp.remaining_bytes(), (size_t)800));  // ~200 chars max
  PyRef pystr(fuzz_bytes_to_str(data, str_enc));
  CHECK(pystr);

  Py_ssize_t len = PyUnicode_GET_LENGTH(pystr);
  if (len > 200) len = 200;

  PyRef neg_one = PyLong_FromLong(-1);
  CHECK(neg_one);
  PyRef empty_str = PyUnicode_FromString("");
  CHECK(empty_str);

  for (Py_ssize_t i = 0; i < len; i++) {
    PyRef ch = PyUnicode_Substring(pystr, i, i + 1);
    if (!ch) { PyErr_Clear(); continue; }

    if (func_mask & 0x01) {
      PyRef r = PyObject_CallFunction(ud_category, "O", (PyObject *)ch);
      if (PyErr_Occurred()) PyErr_Clear();
    }
    if (func_mask & 0x02) {
      PyRef r = PyObject_CallFunction(ud_bidirectional, "O", (PyObject *)ch);
      if (PyErr_Occurred()) PyErr_Clear();
    }
    if (func_mask & 0x04) {
      PyRef r = PyObject_CallFunction(ud_numeric, "OO",
                                      (PyObject *)ch, (PyObject *)neg_one);
      if (PyErr_Occurred()) PyErr_Clear();
    }
    if (func_mask & 0x08) {
      PyRef r = PyObject_CallFunction(ud_decimal, "OO",
                                      (PyObject *)ch, (PyObject *)neg_one);
      if (PyErr_Occurred()) PyErr_Clear();
    }
    if (func_mask & 0x10) {
      PyRef r = PyObject_CallFunction(ud_combining, "O", (PyObject *)ch);
      if (PyErr_Occurred()) PyErr_Clear();
    }
    if (func_mask & 0x20) {
      PyRef r = PyObject_CallFunction(ud_east_asian_width, "O",
                                      (PyObject *)ch);
      if (PyErr_Occurred()) PyErr_Clear();
    }
    if (func_mask & 0x40) {
      PyRef r = PyObject_CallFunction(ud_mirrored, "O", (PyObject *)ch);
      if (PyErr_Occurred()) PyErr_Clear();
    }
    if (func_mask & 0x80) {
      PyRef r = PyObject_CallFunction(ud_name, "OO",
                                      (PyObject *)ch, (PyObject *)empty_str);
      if (PyErr_Occurred()) PyErr_Clear();
      PyRef r2 = PyObject_CallFunction(ud_decomposition, "O",
                                       (PyObject *)ch);
      if (PyErr_Occurred()) PyErr_Clear();
    }
  }
}

// OP_UNICODEDATA_NORMALIZE: FDP selects normalization form from
// {NFC, NFD, NFKC, NFKD}, calls normalize() and is_normalized().
// Optionally calls ucd_3_2_0.normalize() and lookup().
static void op_unicodedata_normalize(FuzzedDataProvider &fdp) {
  static const char *kForms[] = {"NFC", "NFD", "NFKC", "NFKD"};
  int form_idx = fdp.ConsumeIntegralInRange<int>(0, 3);
  int str_enc = fdp.ConsumeIntegralInRange<int>(0, 3);
  bool try_ucd = fdp.ConsumeBool();
  bool try_lookup = fdp.ConsumeBool();
  std::string data = fdp.ConsumeBytesAsString(
      std::min(fdp.remaining_bytes(), (size_t)10000));
  PyRef pystr(fuzz_bytes_to_str(data, str_enc));
  CHECK(pystr);

  const char *form = kForms[form_idx];

  // normalize(form, str)
  {
    PyRef r = PyObject_CallFunction(ud_normalize, "sO",
                                    form, (PyObject *)pystr);
    if (PyErr_Occurred()) PyErr_Clear();
  }

  // is_normalized(form, str)
  {
    PyRef r = PyObject_CallFunction(ud_is_normalized, "sO",
                                    form, (PyObject *)pystr);
    if (PyErr_Occurred()) PyErr_Clear();
  }

  // ucd_3_2_0.normalize('NFC', str)
  if (try_ucd) {
    PyRef r = PyObject_CallMethod(ud_ucd_3_2_0, "normalize", "sO",
                                  "NFC", (PyObject *)pystr);
    if (PyErr_Occurred()) PyErr_Clear();
  }

  // lookup(str)
  if (try_lookup) {
    PyRef r = PyObject_CallFunction(ud_lookup, "O", (PyObject *)pystr);
    if (PyErr_Occurred()) PyErr_Clear();
  }
}

// OP_STRINGIO: Create io.StringIO(), write fuzz str, then exercise
// read/readline/readlines/truncate/iteration. Exercises _io/stringio.c.
static void op_stringio(FuzzedDataProvider &fdp) {
  int str_enc = fdp.ConsumeIntegralInRange<int>(0, 3);
  int variant = fdp.ConsumeIntegralInRange<int>(0, 2);
  std::string data = fdp.ConsumeBytesAsString(
      std::min(fdp.remaining_bytes(), (size_t)10000));
  PyRef pystr(fuzz_bytes_to_str(data, str_enc));
  CHECK(pystr);

  PyRef sio = PyObject_CallFunction(stringio_ctor, NULL);
  CHECK(sio);

  // Write the fuzz string.
  PyRef wr = PyObject_CallMethod(sio, "write", "O", (PyObject *)pystr);
  if (!wr) { PyErr_Clear(); return; }

  // Seek to start.
  PyRef sk = PyObject_CallMethod(sio, "seek", "i", 0);
  if (!sk) { PyErr_Clear(); return; }

  switch (variant) {
    case 0: {
      // read + getvalue
      PyRef r1 = PyObject_CallMethod(sio, "read", NULL);
      if (PyErr_Occurred()) PyErr_Clear();
      PyRef r2 = PyObject_CallMethod(sio, "getvalue", NULL);
      if (PyErr_Occurred()) PyErr_Clear();
      break;
    }
    case 1: {
      // readline x3 + readlines
      for (int i = 0; i < 3; i++) {
        PyRef r = PyObject_CallMethod(sio, "readline", NULL);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      PyRef sk2 = PyObject_CallMethod(sio, "seek", "i", 0);
      if (PyErr_Occurred()) PyErr_Clear();
      PyRef r = PyObject_CallMethod(sio, "readlines", NULL);
      if (PyErr_Occurred()) PyErr_Clear();
      break;
    }
    case 2: {
      // truncate + tell + iteration
      Py_ssize_t slen = PyUnicode_GET_LENGTH(pystr);
      long trunc_at = slen < 64 ? slen : 64;
      PyRef tr = PyObject_CallMethod(sio, "truncate", "l", trunc_at);
      if (PyErr_Occurred()) PyErr_Clear();
      PyRef tl = PyObject_CallMethod(sio, "tell", NULL);
      if (PyErr_Occurred()) PyErr_Clear();
      PyRef sk2 = PyObject_CallMethod(sio, "seek", "i", 0);
      if (PyErr_Occurred()) PyErr_Clear();
      // Iterate.
      PyRef it = PyObject_GetIter(sio);
      if (it) {
        PyObject *line;
        while ((line = PyIter_Next(it)) != NULL)
          Py_DECREF(line);
        if (PyErr_Occurred()) PyErr_Clear();
      } else {
        PyErr_Clear();
      }
      break;
    }
  }

  PyRef cl = PyObject_CallMethod(sio, "close", NULL);
  if (PyErr_Occurred()) PyErr_Clear();
}

// ---------------------------------------------------------------------------
// Dispatch.
// ---------------------------------------------------------------------------

enum Op {
  OP_DATETIME_PARSE,
  OP_DATETIME_FORMAT,
  OP_COLLECTIONS_COUNT,
  OP_UNICODEDATA_CHARINFO,
  OP_UNICODEDATA_NORMALIZE,
  OP_STRINGIO,
  NUM_OPS
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  assert(Py_IsInitialized());
  init_textops();
  if (size < 1 || size > 0x10000) return 0;
  if (PyErr_Occurred()) PyErr_Clear();

  FuzzedDataProvider fdp(data, size);
  switch (fdp.ConsumeIntegralInRange<int>(0, NUM_OPS - 1)) {
    case OP_DATETIME_PARSE:
      op_datetime_parse(fdp);
      break;
    case OP_DATETIME_FORMAT:
      op_datetime_format(fdp);
      break;
    case OP_COLLECTIONS_COUNT:
      op_collections_count(fdp);
      break;
    case OP_UNICODEDATA_CHARINFO:
      op_unicodedata_charinfo(fdp);
      break;
    case OP_UNICODEDATA_NORMALIZE:
      op_unicodedata_normalize(fdp);
      break;
    case OP_STRINGIO:
      op_stringio(fdp);
      break;
  }

  if (++gc_counter % kGcInterval == 0) PyGC_Collect();
  return 0;
}
