// fuzz_helpers.h — Shared infrastructure for CPython fuzz targets.
//
// Each CPython fuzzer binary (.cpp) includes this header. Since each binary
// compiles exactly one .cpp file, all definitions here are safe (no ODR
// issues across translation units).

#ifndef FUZZ_HELPERS_H_
#define FUZZ_HELPERS_H_

#include <Python.h>
#include <assert.h>
#include <stdlib.h>
#include <string>
#include <fuzzer/FuzzedDataProvider.h>

// ---------------------------------------------------------------------------
// LibFuzzer hooks
// ---------------------------------------------------------------------------

// Disable LeakSanitizer. CPython's pymalloc allocator uses custom freelists
// and arenas that LSAN cannot track, causing thousands of false-positive leak
// reports on every fuzzer iteration.
extern "C" int __lsan_is_turned_off(void) { return 1; }

// Initialize the CPython interpreter. Called once by libFuzzer before the
// main fuzzing loop begins.
extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
  PyConfig config;
  PyConfig_InitPythonConfig(&config);
  config.install_signal_handlers = 0;
  config.int_max_str_digits = 8086;
  PyStatus status;
  status =
      PyConfig_SetBytesString(&config, &config.program_name, *argv[0]);
  if (PyStatus_Exception(status)) goto fail;
  status = Py_InitializeFromConfig(&config);
  if (PyStatus_Exception(status)) goto fail;
  PyConfig_Clear(&config);

  // Suppress Python warnings globally — all fuzzers want this.
  PyRun_SimpleString("import warnings; warnings.filterwarnings('ignore')");

  return 0;
fail:
  PyConfig_Clear(&config);
  Py_ExitStatusException(status);
}

// ---------------------------------------------------------------------------
// RAII wrapper and macros
// ---------------------------------------------------------------------------

// RAII wrapper for PyObject*. Prevents reference leaks by calling Py_XDECREF
// in the destructor. Non-copyable, move-enabled.
struct PyRef {
  PyObject *p;
  PyRef(PyObject *o = nullptr) : p(o) {}
  ~PyRef() { Py_XDECREF(p); }
  operator PyObject *() const { return p; }
  explicit operator bool() const { return p != nullptr; }

  PyRef(const PyRef &) = delete;
  PyRef &operator=(const PyRef &) = delete;
  PyRef(PyRef &&o) : p(o.p) { o.p = nullptr; }
  PyRef &operator=(PyRef &&o) {
    Py_XDECREF(p);
    p = o.p;
    o.p = nullptr;
    return *this;
  }
};

// Bail out of the current operation if a Python call returns NULL/false.
// Clears the pending Python exception so the next iteration starts clean.
#define CHECK(x)             \
  do {                       \
    if (!(x)) {              \
      PyErr_Clear();         \
      return;                \
    }                        \
  } while (0)

// Expand a std::string into (const char*, Py_ssize_t) for "y#" format codes.
#define Y(s) (s).data(), (Py_ssize_t)(s).size()

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Import mod.attr and return a new reference. Aborts on failure — called only
// during one-time init, so missing modules indicate a broken build.
static PyObject *import_attr(const char *mod, const char *attr) {
  PyObject *m = PyImport_ImportModule(mod);
  if (!m) {
    PyErr_Print();
    abort();
  }
  PyObject *a = PyObject_GetAttrString(m, attr);
  Py_DECREF(m);
  if (!a) {
    PyErr_Print();
    abort();
  }
  return a;
}

// Convert raw fuzz bytes to a Python str using a fuzz-chosen decoding.
// Different decodings give the fuzzer control over different codepoint ranges:
//   0 — Latin-1:   lossless 1:1 byte-to-codepoint (U+0000-U+00FF)
//   1 — UTF-8:     variable-width, full Unicode (invalid bytes -> U+FFFD)
//   2 — UTF-16-LE: 2 bytes per codepoint, covers BMP including CJK ranges
//   3 — UTF-32-LE: 4 bytes per codepoint, full Unicode incl. supplementary
static PyObject *fuzz_bytes_to_str(const std::string &data, int method) {
  switch (method & 3) {
    case 0:
      return PyUnicode_DecodeLatin1(Y(data), NULL);
    case 1:
      return PyUnicode_DecodeUTF8(Y(data), "replace");
    case 2: {
      int order = -1;  // little-endian
      return PyUnicode_DecodeUTF16(
          data.data(), data.size(), "replace", &order);
    }
    default: {
      int order = -1;  // little-endian
      return PyUnicode_DecodeUTF32(
          data.data(), data.size(), "replace", &order);
    }
  }
}

// Run a Python code string and extract a named attribute from the resulting
// globals dict. Returns a new reference. Aborts on failure — called only
// during one-time init.
static PyObject *run_python_and_get(const char *code, const char *name) {
  PyObject *globals = PyDict_New();
  if (!globals) { PyErr_Print(); abort(); }
  PyDict_SetItemString(globals, "__builtins__", PyEval_GetBuiltins());
  PyObject *r = PyRun_String(code, Py_file_input, globals, globals);
  if (!r) { PyErr_Print(); Py_DECREF(globals); abort(); }
  Py_DECREF(r);
  PyObject *attr = PyDict_GetItemString(globals, name);  // borrowed
  if (!attr) { PyErr_Print(); Py_DECREF(globals); abort(); }
  Py_INCREF(attr);
  Py_DECREF(globals);
  return attr;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

// Maximum fuzz input size (1 MB).
static constexpr size_t kMaxInputSize = 0x100000;

#endif  // FUZZ_HELPERS_H_
