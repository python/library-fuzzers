// fuzz_json_decode.cpp — Fuzzer for CPython's _json C extension module (decoding).
//
// This fuzzer exercises the following CPython C extension module via
// its Python API, called through the Python C API from C++:
//
//   _json               — json.loads(str), JSONDecoder().decode(str),
//                          JSONDecoder().raw_decode(str)
//
// The first two bytes of fuzz input select string encoding and target
// function. Remaining bytes become the input string. Each target makes
// a single call. Exercises the _json C acceleration module's scanning,
// string unescaping, number parsing, and recursive container building.
//
// All module functions are imported once during init and cached as static
// PyObject* pointers. PyRef (RAII) prevents reference leaks.
// Max input size: 64 KB.

#include "fuzz_helpers.h"

static PyObject *json_loads, *json_JSONDecoder;

static int initialized = 0;

static void init_json_decode(void) {
  if (initialized) return;

  json_loads = import_attr("json", "loads");
  json_JSONDecoder = import_attr("json", "JSONDecoder");
  assert(!PyErr_Occurred());
  initialized = 1;
}

// op_json_decode: the fuzzer selects one of 3 targets — json.loads(str),
// JSONDecoder().decode(str), or JSONDecoder().raw_decode(str).
// Exercises the _json C acceleration module's decoding paths.
static void op_json_decode(FuzzedDataProvider &fdp) {
  int str_enc = fdp.ConsumeIntegralInRange<int>(0, 3);
  enum { LOADS, DECODE, RAW_DECODE, NUM_TARGETS };
  int target_fn = fdp.ConsumeIntegralInRange<int>(0, NUM_TARGETS - 1);
  if (fdp.remaining_bytes() == 0) return;
  std::string data = fdp.ConsumeRemainingBytesAsString();
  PyRef pystr(fuzz_bytes_to_str(data, str_enc));
  CHECK(pystr);

  switch (target_fn) {
    case LOADS: {
      // json.loads(str)
      PyRef r = PyObject_CallFunction(json_loads, "O", (PyObject *)pystr);
      break;
    }
    case DECODE: {
      // JSONDecoder().decode(str)
      PyRef dec = PyObject_CallFunction(json_JSONDecoder, NULL);
      CHECK(dec);
      PyRef r = PyObject_CallMethod(dec, "decode", "O", (PyObject *)pystr);
      break;
    }
    case RAW_DECODE: {
      // JSONDecoder().raw_decode(str)
      PyRef dec = PyObject_CallFunction(json_JSONDecoder, NULL);
      CHECK(dec);
      PyRef r = PyObject_CallMethod(dec, "raw_decode", "O", (PyObject *)pystr);
      break;
    }
  }
  if (PyErr_Occurred()) PyErr_Clear();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  assert(Py_IsInitialized());
  init_json_decode();
  if (size < 1 || size > 0x10000) return 0;
  if (PyErr_Occurred()) PyErr_Clear();

  FuzzedDataProvider fdp(data, size);
  op_json_decode(fdp);

  return 0;
}
