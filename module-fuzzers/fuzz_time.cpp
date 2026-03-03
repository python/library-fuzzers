// fuzz_time.cpp — Fuzzer for CPython's time C extension module.
//
// This fuzzer exercises the following CPython C extension module via
// its Python API, called through the Python C API from C++:
//
//   time                — strftime with fuzz format, strptime with fuzz input,
//                          strptime with fuzz format
//
// All module functions are imported once during init and cached as static
// PyObject* pointers. PyRef (RAII) prevents reference leaks.
// Max input size: 64 KB.

#include "fuzz_helpers.h"

static PyObject *time_strftime, *time_strptime, *time_localtime;

static int initialized = 0;

static void init_time(void) {
  if (initialized) return;

  time_strftime = import_attr("time", "strftime");
  time_strptime = import_attr("time", "strptime");
  time_localtime = import_attr("time", "localtime");
  assert(!PyErr_Occurred());
  initialized = 1;
}

// op_time: FDP selects variant — strftime with fuzz format, strptime with
// fuzz input, or strptime with fuzz format. Exercises the time C module.
static void op_time(FuzzedDataProvider &fdp) {
  int str_enc = fdp.ConsumeIntegralInRange<int>(0, 3);
  enum { STRFTIME, STRPTIME_INPUT, STRPTIME_FORMAT, NUM_TARGETS };
  int target_fn = fdp.ConsumeIntegralInRange<int>(0, NUM_TARGETS - 1);
  if (fdp.remaining_bytes() == 0) return;
  std::string data = fdp.ConsumeRemainingBytesAsString();
  PyRef pystr(fuzz_bytes_to_str(data, str_enc));
  CHECK(pystr);

  switch (target_fn) {
    case STRFTIME: {
      // time.strftime(str, time.localtime())
      PyRef lt = PyObject_CallFunction(time_localtime, NULL);
      CHECK(lt);
      // Use non-empty format.
      Py_ssize_t slen = PyUnicode_GET_LENGTH(pystr);
      PyObject *fmt = slen > 0 ? (PyObject *)pystr : NULL;
      if (!fmt) {
        PyRef def_fmt = PyUnicode_FromString("%Y");
        CHECK(def_fmt);
        PyRef r = PyObject_CallFunction(time_strftime, "OO",
                                        (PyObject *)def_fmt, (PyObject *)lt);
      } else {
        PyRef r = PyObject_CallFunction(time_strftime, "OO",
                                        fmt, (PyObject *)lt);
      }
      break;
    }
    case STRPTIME_INPUT: {
      // time.strptime(str, '%Y-%m-%d %H:%M:%S')
      PyRef r = PyObject_CallFunction(time_strptime, "Os",
                                      (PyObject *)pystr,
                                      "%Y-%m-%d %H:%M:%S");
      break;
    }
    case STRPTIME_FORMAT: {
      // time.strptime('2024-01-15 12:30:00', str)
      // Use non-empty format.
      Py_ssize_t slen = PyUnicode_GET_LENGTH(pystr);
      PyObject *fmt = slen > 0 ? (PyObject *)pystr : NULL;
      if (!fmt) {
        PyRef def_fmt = PyUnicode_FromString("%Y-%m-%d %H:%M:%S");
        CHECK(def_fmt);
        PyRef r = PyObject_CallFunction(time_strptime, "sO",
                                        "2024-01-15 12:30:00",
                                        (PyObject *)def_fmt);
      } else {
        PyRef r = PyObject_CallFunction(time_strptime, "sO",
                                        "2024-01-15 12:30:00", fmt);
      }
      break;
    }
  }
  if (PyErr_Occurred()) PyErr_Clear();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  assert(Py_IsInitialized());
  init_time();
  if (size < 1 || size > 0x10000) return 0;
  if (PyErr_Occurred()) PyErr_Clear();

  FuzzedDataProvider fdp(data, size);
  op_time(fdp);

  return 0;
}
