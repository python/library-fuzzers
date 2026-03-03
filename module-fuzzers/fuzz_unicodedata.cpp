// fuzz_unicodedata.cpp — Fuzzer for CPython's unicodedata C extension module.
//
// This fuzzer exercises the following CPython C extension module via
// its Python API, called through the Python C API from C++:
//
//   unicodedata          — category, bidirectional, numeric, decimal,
//                          combining, east_asian_width, mirrored, name,
//                          decomposition, normalize, is_normalized, lookup,
//                          ucd_3_2_0.normalize
//
// The first two bytes of fuzz input select string encoding and target
// function (one of 13). Remaining bytes become the input string.
// Each target makes a single call.
//
// All module functions are imported once during init and cached as static
// PyObject* pointers. PyRef (RAII) prevents reference leaks.
// Max input size: 64 KB.

#include "fuzz_helpers.h"

// unicodedata
static PyObject *ud_category, *ud_bidirectional, *ud_normalize, *ud_numeric;
static PyObject *ud_lookup, *ud_name, *ud_decomposition, *ud_is_normalized;
static PyObject *ud_east_asian_width, *ud_mirrored, *ud_decimal, *ud_combining;
static PyObject *ud_ucd_3_2_0;

static int initialized = 0;

static void init_unicodedata(void) {
  if (initialized) return;

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
  assert(!PyErr_Occurred());
  initialized = 1;
}

// op_unicodedata: the fuzzer selects one of 13 targets — 9 single-character
// functions (category, bidirectional, numeric, decimal, combining,
// east_asian_width, mirrored, name, decomposition) or 4 whole-string
// functions (normalize, is_normalized, ucd_3_2_0.normalize, lookup).
// Each target makes a single call. Exercises the unicodedata C module's
// character-info, normalization, and name-lookup code paths.
static void op_unicodedata(FuzzedDataProvider &fdp) {
  int str_enc = fdp.ConsumeIntegralInRange<int>(0, 3);
  enum {
    CATEGORY, BIDIRECTIONAL, NUMERIC, DECIMAL, COMBINING,
    EAST_ASIAN_WIDTH, MIRRORED, NAME, DECOMPOSITION,
    NORMALIZE, IS_NORMALIZED, UCD_NORMALIZE, LOOKUP,
    NUM_TARGETS
  };
  int target_fn = fdp.ConsumeIntegralInRange<int>(0, NUM_TARGETS - 1);
  if (fdp.remaining_bytes() == 0) return;
  std::string data = fdp.ConsumeRemainingBytesAsString();
  PyRef pystr(fuzz_bytes_to_str(data, str_enc));
  CHECK(pystr);

  static const char *kForms[] = {"NFC", "NFD", "NFKC", "NFKD"};

  switch (target_fn) {
    case CATEGORY: {
      PyRef r = PyObject_CallFunction(ud_category, "O", (PyObject *)pystr);
      break;
    }
    case BIDIRECTIONAL: {
      PyRef r = PyObject_CallFunction(ud_bidirectional, "O", (PyObject *)pystr);
      break;
    }
    case NUMERIC: {
      PyRef dflt = PyLong_FromLong(fdp.ConsumeIntegral<int32_t>());
      CHECK(dflt);
      PyRef r = PyObject_CallFunction(ud_numeric, "OO",
                                      (PyObject *)pystr, (PyObject *)dflt);
      break;
    }
    case DECIMAL: {
      PyRef dflt = PyLong_FromLong(fdp.ConsumeIntegral<int32_t>());
      CHECK(dflt);
      PyRef r = PyObject_CallFunction(ud_decimal, "OO",
                                      (PyObject *)pystr, (PyObject *)dflt);
      break;
    }
    case COMBINING: {
      PyRef r = PyObject_CallFunction(ud_combining, "O", (PyObject *)pystr);
      break;
    }
    case EAST_ASIAN_WIDTH: {
      PyRef r = PyObject_CallFunction(ud_east_asian_width, "O",
                                      (PyObject *)pystr);
      break;
    }
    case MIRRORED: {
      PyRef r = PyObject_CallFunction(ud_mirrored, "O", (PyObject *)pystr);
      break;
    }
    case NAME: {
      PyRef empty_str = PyUnicode_FromString("");
      CHECK(empty_str);
      PyRef r = PyObject_CallFunction(ud_name, "OO",
                                      (PyObject *)pystr, (PyObject *)empty_str);
      break;
    }
    case DECOMPOSITION: {
      PyRef r = PyObject_CallFunction(ud_decomposition, "O",
                                      (PyObject *)pystr);
      break;
    }
    case NORMALIZE: {
      const char *form = kForms[str_enc & 3];
      PyRef r = PyObject_CallFunction(ud_normalize, "sO",
                                      form, (PyObject *)pystr);
      break;
    }
    case IS_NORMALIZED: {
      const char *form = kForms[str_enc & 3];
      PyRef r = PyObject_CallFunction(ud_is_normalized, "sO",
                                      form, (PyObject *)pystr);
      break;
    }
    case UCD_NORMALIZE: {
      PyRef r = PyObject_CallMethod(ud_ucd_3_2_0, "normalize", "sO",
                                    "NFC", (PyObject *)pystr);
      break;
    }
    case LOOKUP: {
      PyRef r = PyObject_CallFunction(ud_lookup, "O", (PyObject *)pystr);
      break;
    }
  }
  if (PyErr_Occurred()) PyErr_Clear();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  assert(Py_IsInitialized());
  init_unicodedata();
  if (size < 1 || size > 0x10000) return 0;
  if (PyErr_Occurred()) PyErr_Clear();

  FuzzedDataProvider fdp(data, size);
  op_unicodedata(fdp);

  return 0;
}
