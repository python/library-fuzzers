// fuzz_json_encode.cpp — Fuzzer for CPython's _json C extension module (encoding).
//
// This fuzzer exercises the following CPython C extension module via
// its Python API, called through the Python C API from C++:
//
//   _json               — json.dumps(str), json.dumps({k:v,...} with
//                          fuzz-typed keys/values),
//                          json.dumps([str,...] with 1-10 unique strings),
//                          JSONEncoder(ensure_ascii=True/False).encode(),
//                          JSONEncoder(sort_keys, indent, ensure_ascii).encode()
//
// All module functions are imported once during init and cached as static
// PyObject* pointers. PyRef (RAII) prevents reference leaks.
// Max input size: 64 KB.

#include "fuzz_helpers.h"

static PyObject *json_dumps, *json_JSONEncoder;

static int initialized = 0;

static void init_json(void) {
  if (initialized) return;

  json_dumps = import_attr("json", "dumps");
  json_JSONEncoder = import_attr("json", "JSONEncoder");
  assert(!PyErr_Occurred());
  initialized = 1;
}

// Build a fuzz-chosen JSON-serializable Python object.
// key_only=true restricts to hashable types (str, int, float, bool, None).
// depth limits recursion for nested list/dict values.
static PyObject *make_json_value(FuzzedDataProvider &fdp, int str_enc,
                                 bool key_only, int depth = 0) {
  enum { T_STR, T_INT, T_FLOAT, T_BOOL, T_NONE, T_LIST, T_DICT, NUM_TYPES };
  int max_type = (key_only || depth >= 3) ? T_NONE : (NUM_TYPES - 1);
  int t = fdp.ConsumeIntegralInRange<int>(0, max_type);
  switch (t) {
    case T_STR: {
      size_t slen = (fdp.ConsumeIntegral<uint16_t>() % 10000) + 1;
      std::string s = fdp.ConsumeBytesAsString(slen);
      return fuzz_bytes_to_str(s, str_enc);
    }
    case T_INT:
      return PyLong_FromLong(fdp.ConsumeIntegral<int32_t>());
    case T_FLOAT:
      return PyFloat_FromDouble(fdp.ConsumeFloatingPoint<double>());
    case T_BOOL: {
      PyObject *b = fdp.ConsumeBool() ? Py_True : Py_False;
      Py_INCREF(b);
      return b;
    }
    case T_NONE:
      Py_INCREF(Py_None);
      return Py_None;
    case T_LIST: {
      int count = fdp.ConsumeIntegralInRange<int>(0, 3);
      PyObject *lst = PyList_New(0);
      if (!lst) return NULL;
      for (int i = 0; i < count; i++) {
        PyObject *item = make_json_value(fdp, str_enc, false, depth + 1);
        if (!item) { PyErr_Clear(); continue; }
        PyList_Append(lst, item);
        Py_DECREF(item);
      }
      return lst;
    }
    case T_DICT: {
      int count = fdp.ConsumeIntegralInRange<int>(0, 3);
      PyObject *d = PyDict_New();
      if (!d) return NULL;
      for (int i = 0; i < count; i++) {
        PyObject *k = make_json_value(fdp, str_enc, true, depth + 1);
        if (!k) { PyErr_Clear(); continue; }
        PyObject *v = make_json_value(fdp, str_enc, false, depth + 1);
        if (!v) { Py_DECREF(k); PyErr_Clear(); continue; }
        PyDict_SetItem(d, k, v);
        Py_DECREF(k);
        Py_DECREF(v);
      }
      return d;
    }
    default:
      Py_INCREF(Py_None);
      return Py_None;
  }
}

// op_json_encode: the fuzzer selects the target: json.dumps(str),
// json.dumps({k:v,...} with 1-5 fuzz-typed entries),
// json.dumps([1-10 unique strs]), or JSONEncoder with options.
// Exercises the _json C acceleration module's encoding paths.
static void op_json_encode(FuzzedDataProvider &fdp) {
  int str_enc = fdp.ConsumeIntegralInRange<int>(0, 3);
  enum { DUMPS_STR, DUMPS_DICT, DUMPS_LIST, ENCODE_NO_ASCII, ENCODE_ASCII, ENCODE_OPTS, NUM_TARGETS };
  int target_fn = fdp.ConsumeIntegralInRange<int>(0, NUM_TARGETS - 1);
  if (fdp.remaining_bytes() == 0) return;
  size_t data_len = fdp.ConsumeIntegralInRange<size_t>(
      1, std::min(fdp.remaining_bytes(), (size_t)10000));
  std::string data = fdp.ConsumeBytesAsString(data_len);
  PyRef pystr(fuzz_bytes_to_str(data, str_enc));
  CHECK(pystr);

  switch (target_fn) {
    case DUMPS_STR: {
      // json.dumps(str)
      PyRef r = PyObject_CallFunction(json_dumps, "O", (PyObject *)pystr);
      break;
    }
    case DUMPS_DICT: {
      // json.dumps({k: v, ...}) — 1 to 5 entries, fuzz-chosen types.
      int count = fdp.ConsumeIntegralInRange<int>(1, 5);
      PyRef d = PyDict_New();
      CHECK(d);
      for (int i = 0; i < count; i++) {
        PyRef k(make_json_value(fdp, str_enc, true));
        if (!k) { PyErr_Clear(); continue; }
        PyRef v(make_json_value(fdp, str_enc, false));
        if (!v) { PyErr_Clear(); continue; }
        PyDict_SetItem(d, k, v);
      }
      PyRef r = PyObject_CallFunction(json_dumps, "O", (PyObject *)d);
      break;
    }
    case DUMPS_LIST: {
      // json.dumps([str, str, ...]) — 1 to 10 unique fuzz strings.
      int count = fdp.ConsumeIntegralInRange<int>(1, 10);
      PyRef lst = PyList_New(0);
      CHECK(lst);
      for (int i = 0; i < count; i++) {
        size_t slen = (fdp.ConsumeIntegral<uint8_t>() % 10) + 1;
        std::string s = fdp.ConsumeBytesAsString(slen);
        PyRef item(fuzz_bytes_to_str(s, str_enc));
        if (!item) { PyErr_Clear(); continue; }
        PyList_Append(lst, item);
      }
      PyRef r = PyObject_CallFunction(json_dumps, "O", (PyObject *)lst);
      break;
    }
    case ENCODE_NO_ASCII: {
      // JSONEncoder(ensure_ascii=False).encode(str)
      PyRef kwargs = PyDict_New();
      CHECK(kwargs);
      PyDict_SetItemString(kwargs, "ensure_ascii", Py_False);
      PyRef empty = PyTuple_New(0);
      CHECK(empty);
      PyRef enc = PyObject_Call(json_JSONEncoder, empty, kwargs);
      CHECK(enc);
      PyRef r = PyObject_CallMethod(enc, "encode", "O", (PyObject *)pystr);
      break;
    }
    case ENCODE_ASCII: {
      // JSONEncoder(ensure_ascii=True).encode(str)
      PyRef kwargs = PyDict_New();
      CHECK(kwargs);
      PyDict_SetItemString(kwargs, "ensure_ascii", Py_True);
      PyRef empty = PyTuple_New(0);
      CHECK(empty);
      PyRef enc = PyObject_Call(json_JSONEncoder, empty, kwargs);
      CHECK(enc);
      PyRef r = PyObject_CallMethod(enc, "encode", "O", (PyObject *)pystr);
      break;
    }
    case ENCODE_OPTS: {
      // JSONEncoder(sort_keys=True, indent=2, ensure_ascii=False).encode({s:s})
      PyRef kwargs = PyDict_New();
      CHECK(kwargs);
      PyDict_SetItemString(kwargs, "sort_keys", Py_True);
      PyRef indent = PyLong_FromLong(2);
      CHECK(indent);
      PyDict_SetItemString(kwargs, "indent", indent);
      PyDict_SetItemString(kwargs, "ensure_ascii", Py_False);
      PyRef empty = PyTuple_New(0);
      CHECK(empty);
      PyRef enc = PyObject_Call(json_JSONEncoder, empty, kwargs);
      CHECK(enc);
      PyRef d = PyDict_New();
      CHECK(d);
      PyDict_SetItem(d, pystr, pystr);
      PyRef r = PyObject_CallMethod(enc, "encode", "O", (PyObject *)d);
      break;
    }
  }
  if (PyErr_Occurred()) PyErr_Clear();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  assert(Py_IsInitialized());
  init_json();
  if (size < 1 || size > 0x10000) return 0;
  if (PyErr_Occurred()) PyErr_Clear();

  FuzzedDataProvider fdp(data, size);
  op_json_encode(fdp);

  return 0;
}
