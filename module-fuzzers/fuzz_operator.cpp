// fuzz_operator.cpp — Fuzzer for CPython's _operator C extension module.
//
// This fuzzer exercises the following CPython C extension module via
// its Python API, called through the Python C API from C++:
//
//   _operator           — lt, gt, eq, ne, contains, countOf, indexOf,
//                          length_hint, concat, getitem, methodcaller
//
// All module functions are imported once during init and cached as static
// PyObject* pointers. PyRef (RAII) prevents reference leaks.
// Max input size: 64 KB.

#include "fuzz_helpers.h"

static PyObject *op_lt, *op_gt, *op_eq, *op_ne;
static PyObject *op_contains, *op_countOf, *op_indexOf, *op_length_hint;
static PyObject *op_concat, *op_getitem, *op_methodcaller;

static int initialized = 0;

static void init_operator(void) {
  if (initialized) return;

  op_lt = import_attr("operator", "lt");
  op_gt = import_attr("operator", "gt");
  op_eq = import_attr("operator", "eq");
  op_ne = import_attr("operator", "ne");
  op_contains = import_attr("operator", "contains");
  op_countOf = import_attr("operator", "countOf");
  op_indexOf = import_attr("operator", "indexOf");
  op_length_hint = import_attr("operator", "length_hint");
  op_concat = import_attr("operator", "concat");
  op_getitem = import_attr("operator", "getitem");
  op_methodcaller = import_attr("operator", "methodcaller");
  assert(!PyErr_Occurred());
  initialized = 1;
}

// op_operator: fuzzer selects operator variant — comparisons, sequence ops,
// concat, getitem, methodcaller. Exercises the _operator C module.
static void op_operator(FuzzedDataProvider &fdp) {
  enum { COMPARISONS, SEQUENCE_OPS, CONCAT, GETITEM, METHODCALLER, CONTAINS, NUM_TARGETS };
  int target_fn = fdp.ConsumeIntegralInRange<int>(0, NUM_TARGETS - 1);
  if (fdp.remaining_bytes() == 0) return;
  size_t data_len = fdp.ConsumeIntegralInRange<size_t>(
      1, std::min(fdp.remaining_bytes(), (size_t)10000));
  std::string data = fdp.ConsumeBytesAsString(data_len);

  PyRef pydata = PyBytes_FromStringAndSize(Y(data));
  CHECK(pydata);

  switch (target_fn) {
    case COMPARISONS: {
      // Comparisons: lt/gt/eq/ne(data, other)
      std::string other = fdp.ConsumeRemainingBytesAsString();
      PyRef pyother = PyBytes_FromStringAndSize(Y(other));
      CHECK(pyother);
      {
        PyRef r = PyObject_CallFunction(op_lt, "OO",
                                        (PyObject *)pydata, (PyObject *)pyother);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        PyRef r = PyObject_CallFunction(op_gt, "OO",
                                        (PyObject *)pydata, (PyObject *)pyother);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        PyRef r = PyObject_CallFunction(op_eq, "OO",
                                        (PyObject *)pydata, (PyObject *)pyother);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        PyRef r = PyObject_CallFunction(op_ne, "OO",
                                        (PyObject *)pydata, (PyObject *)pyother);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      break;
    }
    case SEQUENCE_OPS: {
      // Sequence ops: contains, countOf, indexOf, length_hint
      if (data.empty()) break;
      int byte = fdp.ConsumeIntegralInRange<int>(0, 255);
      PyRef byte_val = PyLong_FromLong(byte);
      CHECK(byte_val);
      {
        PyRef r = PyObject_CallFunction(op_contains, "OO",
                                        (PyObject *)pydata,
                                        (PyObject *)byte_val);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        PyRef r = PyObject_CallFunction(op_countOf, "OO",
                                        (PyObject *)pydata,
                                        (PyObject *)byte_val);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        PyRef r = PyObject_CallFunction(op_indexOf, "OO",
                                        (PyObject *)pydata,
                                        (PyObject *)byte_val);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        PyRef r = PyObject_CallFunction(op_length_hint, "O",
                                        (PyObject *)pydata);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      break;
    }
    case CONCAT: {
      // concat(data, other)
      std::string other = fdp.ConsumeRemainingBytesAsString();
      PyRef pyother = PyBytes_FromStringAndSize(Y(other));
      CHECK(pyother);
      PyRef r = PyObject_CallFunction(op_concat, "OO",
                                      (PyObject *)pydata, (PyObject *)pyother);
      if (PyErr_Occurred()) PyErr_Clear();
      break;
    }
    case GETITEM: {
      // getitem(data, idx) + getitem(data, slice)
      if (data.empty()) break;
      long idx = fdp.ConsumeIntegralInRange<long>(0, data.size() - 1);
      PyRef pyidx = PyLong_FromLong(idx);
      CHECK(pyidx);
      {
        PyRef r = PyObject_CallFunction(op_getitem, "OO",
                                        (PyObject *)pydata, (PyObject *)pyidx);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        long stop = fdp.ConsumeIntegralInRange<long>(0, data.size());
        PyRef pystop = PyLong_FromLong(stop);
        CHECK(pystop);
        PyRef zero = PyLong_FromLong(0);
        CHECK(zero);
        PyRef sl = PySlice_New(zero, pystop, NULL);
        CHECK(sl);
        PyRef r = PyObject_CallFunction(op_getitem, "OO",
                                        (PyObject *)pydata, (PyObject *)sl);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      break;
    }
    case METHODCALLER: {
      // methodcaller('upper')(str) + methodcaller('encode', 'utf-8')(str)
      int str_enc = fdp.ConsumeIntegralInRange<int>(0, 3);
      std::string str_data = fdp.ConsumeRemainingBytesAsString();
      PyRef pystr(fuzz_bytes_to_str(str_data, str_enc));
      CHECK(pystr);
      {
        PyRef mc = PyObject_CallFunction(op_methodcaller, "s", "upper");
        CHECK(mc);
        PyRef r = PyObject_CallFunction(mc, "O", (PyObject *)pystr);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        PyRef mc = PyObject_CallFunction(op_methodcaller, "ss",
                                         "encode", "utf-8");
        CHECK(mc);
        PyRef r = PyObject_CallFunction(mc, "O", (PyObject *)pystr);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      break;
    }
    case CONTAINS: {
      // contains on bytes with fuzz-driven needle
      std::string needle = fdp.ConsumeRemainingBytesAsString();
      PyRef pyneedle = PyBytes_FromStringAndSize(Y(needle));
      CHECK(pyneedle);
      PyRef r = PyObject_CallFunction(op_contains, "OO",
                                      (PyObject *)pydata, (PyObject *)pyneedle);
      if (PyErr_Occurred()) PyErr_Clear();
      break;
    }
  }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  assert(Py_IsInitialized());
  init_operator();
  if (size < 1 || size > 0x10000) return 0;
  if (PyErr_Occurred()) PyErr_Clear();

  FuzzedDataProvider fdp(data, size);
  op_operator(fdp);

  return 0;
}
