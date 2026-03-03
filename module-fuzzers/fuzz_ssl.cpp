// fuzz_ssl.cpp — Fuzzer for CPython's _ssl C extension module.
//
// This fuzzer exercises the following CPython C extension module via
// its Python API, called through the Python C API from C++:
//
//   _ssl               — ssl.DER_cert_to_PEM_cert(), then optionally
//                         SSLContext(PROTOCOL_TLS_CLIENT).load_verify_locations()
//
// Exercises the OpenSSL certificate parsing path in the _ssl C module.
//
// All module functions are imported once during init and cached as static
// PyObject* pointers. PyRef (RAII) prevents reference leaks.
// Max input size: 1 MB.

#include "fuzz_helpers.h"

static PyObject *ssl_DER_cert_to_PEM_cert, *ssl_SSLContext;
static long ssl_PROTOCOL_TLS_CLIENT_val;

static int initialized = 0;

static void init_ssl(void) {
  if (initialized) return;

  ssl_DER_cert_to_PEM_cert = import_attr("ssl", "DER_cert_to_PEM_cert");
  ssl_SSLContext = import_attr("ssl", "SSLContext");
  {
    PyObject *v = import_attr("ssl", "PROTOCOL_TLS_CLIENT");
    ssl_PROTOCOL_TLS_CLIENT_val = PyLong_AsLong(v);
    Py_DECREF(v);
  }

  assert(!PyErr_Occurred());
  initialized = 1;
}

// op_ssl_cert: Call ssl.DER_cert_to_PEM_cert(data) to attempt DER-to-PEM
// certificate conversion. If successful, create an SSLContext with
// PROTOCOL_TLS_CLIENT and call .load_verify_locations(cadata=pem_string)
// to exercise the OpenSSL certificate parsing path in the _ssl C module.
static void op_ssl_cert(FuzzedDataProvider &fdp) {
  std::string data = fdp.ConsumeRemainingBytesAsString();
  PyRef pydata = PyBytes_FromStringAndSize(Y(data));
  CHECK(pydata);
  PyRef pem = PyObject_CallFunction(ssl_DER_cert_to_PEM_cert, "O",
                                    (PyObject *)pydata);
  if (!pem) {
    PyErr_Clear();
    return;
  }

  // Optionally try to load into SSLContext.
  PyRef ctx = PyObject_CallFunction(ssl_SSLContext, "l",
                                    ssl_PROTOCOL_TLS_CLIENT_val);
  if (!ctx) {
    PyErr_Clear();
    return;
  }

  PyRef kwargs = PyDict_New();
  CHECK(kwargs);
  PyDict_SetItemString(kwargs, "cadata", pem);
  PyRef empty_args = PyTuple_New(0);
  CHECK(empty_args);
  PyRef method = PyObject_GetAttrString(ctx, "load_verify_locations");
  if (!method) {
    PyErr_Clear();
    return;
  }
  PyRef r = PyObject_Call(method, empty_args, kwargs);
  if (PyErr_Occurred()) PyErr_Clear();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  assert(Py_IsInitialized());
  init_ssl();
  if (size < 1 || size > kMaxInputSize) return 0;
  if (PyErr_Occurred()) PyErr_Clear();

  FuzzedDataProvider fdp(data, size);
  op_ssl_cert(fdp);

  return 0;
}
