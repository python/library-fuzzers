// fuzz_locale.cpp — Fuzzer for CPython's _locale C extension module.
//
// This fuzzer exercises the following CPython C extension module via
// its Python API, called through the Python C API from C++:
//
//   _locale             — strxfrm, strcoll
//
// All module functions are imported once during init and cached as static
// PyObject* pointers. PyRef (RAII) prevents reference leaks.
// Max input size: 64 KB.

#include "fuzz_helpers.h"

static PyObject *locale_strxfrm, *locale_strcoll;

static int initialized = 0;

static void init_locale(void) {
  if (initialized) return;

  locale_strxfrm = import_attr("locale", "strxfrm");
  locale_strcoll = import_attr("locale", "strcoll");
  assert(!PyErr_Occurred());
  initialized = 1;
}

// op_locale: fuzz data selects target — strxfrm or strcoll.
// Exercises the _locale C module.
static void op_locale(FuzzedDataProvider &fdp) {
  int str_enc = fdp.ConsumeIntegralInRange<int>(0, 3);

  enum { STRXFRM, STRCOLL, NUM_TARGETS };
  int target_fn = fdp.ConsumeIntegralInRange<int>(0, NUM_TARGETS - 1);

  switch (target_fn) {
    case STRXFRM: {
      // strxfrm: transform a string for locale-aware comparison.
      std::string data = fdp.ConsumeRemainingBytesAsString();
      PyRef pystr(fuzz_bytes_to_str(data, str_enc));
      CHECK(pystr);
      PyRef r = PyObject_CallFunction(locale_strxfrm, "O", (PyObject *)pystr);
      break;
    }
    case STRCOLL: {
      // strcoll: compare two substrings using locale collation rules.
      // Both operands are independently produced from fuzz data.
      int str_enc2 = fdp.ConsumeIntegralInRange<int>(0, 3);
      size_t split = fdp.ConsumeIntegralInRange<size_t>(0, fdp.remaining_bytes());
      std::string data1 = fdp.ConsumeBytesAsString(split);
      std::string data2 = fdp.ConsumeRemainingBytesAsString();
      PyRef pystr1(fuzz_bytes_to_str(data1, str_enc));
      CHECK(pystr1);
      PyRef pystr2(fuzz_bytes_to_str(data2, str_enc2));
      CHECK(pystr2);
      PyRef r = PyObject_CallFunction(locale_strcoll, "OO",
                                      (PyObject *)pystr1, (PyObject *)pystr2);
      break;
    }
  }
  if (PyErr_Occurred()) PyErr_Clear();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  assert(Py_IsInitialized());
  init_locale();
  if (size < 1 || size > 0x10000) return 0;
  if (PyErr_Occurred()) PyErr_Clear();

  FuzzedDataProvider fdp(data, size);
  op_locale(fdp);

  return 0;
}
