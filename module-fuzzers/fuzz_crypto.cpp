// fuzz_crypto.cpp — Fuzzer for CPython's hash and HMAC C extension modules.
//
// This fuzzer exercises the following CPython C extension modules via
// their Python API, called through the Python C API from C++:
//
//   _md5, _sha1, _sha2      — MD5, SHA-1, SHA-224/256/384/512
//   _sha3                    — SHA3-224/256/384/512, SHAKE-128/256
//   _blake2                  — BLAKE2b (64-byte key/16-byte salt/person),
//                              BLAKE2s (32-byte key/8-byte salt/person)
//   _hmac                    — Low-level compute_md5/sha1/sha256/sha512
//   hmac (Python module)     — hmac.new(), hmac.digest(), hmac.compare_digest()
//   hashlib (Python module)  — hashlib.new(), hashlib.pbkdf2_hmac(),
//                              hashlib.file_digest()
//
// The first byte of fuzz input selects one of 13 operation types. Each
// operation consumes further bytes via FuzzedDataProvider to parameterize
// the call (algorithm choice, key/salt/data sizes, action sequences).
//
// Operations fall into two categories:
//
//   Chained — Create a hash/HMAC object, then loop up to 100 actions
//     chosen from: .update(data), .digest(), .hexdigest(), .copy().digest(),
//     and reading .name/.digest_size/.block_size attributes. Used for
//     standard hashes, SHAKE (variable-length digest), BLAKE2 (keyed +
//     variable digest_size), hmac.new(), and hashlib.new().
//
//   One-shot — A single function call: _hmac.compute_*(key, msg),
//     hmac.digest(key, msg, algo), hmac.compare_digest(a, b),
//     hashlib.file_digest(BytesIO, algo), hashlib.pbkdf2_hmac(algo, pw, salt, 1).
//
// All module functions and constructors are imported once during init and
// cached as static PyObject* pointers. PyRef (RAII) prevents reference leaks.
// PyGC_Collect() runs every 200 iterations. Max input size: 1 MB.

#include "fuzz_helpers.h"

// ---------------------------------------------------------------------------
// Cached module objects, initialized once.
// ---------------------------------------------------------------------------

static PyObject *ctor_md5, *ctor_sha1;
static PyObject *ctor_sha224, *ctor_sha256, *ctor_sha384, *ctor_sha512;
static PyObject *ctor_sha3_224, *ctor_sha3_256, *ctor_sha3_384, *ctor_sha3_512;
static PyObject *ctor_shake_128, *ctor_shake_256;
static PyObject *ctor_blake2b, *ctor_blake2s;

static PyObject **all_hash_ctors[] = {
  &ctor_md5, &ctor_sha1, &ctor_sha224, &ctor_sha256,
  &ctor_sha384, &ctor_sha512, &ctor_sha3_224, &ctor_sha3_256,
  &ctor_sha3_384, &ctor_sha3_512, &ctor_blake2b, &ctor_blake2s,
};
static constexpr int kNumHashCtors =
    sizeof(all_hash_ctors) / sizeof(all_hash_ctors[0]);

static PyObject **shake_ctors[] = {&ctor_shake_128, &ctor_shake_256};
static constexpr int kNumShakeCtors = 2;

static PyObject *hmac_compute_funcs[4];
static int num_hmac_compute_funcs = 0;

static PyObject *hashlib_new, *hashlib_pbkdf2_hmac, *hashlib_file_digest;
static PyObject *py_hmac_new, *py_hmac_digest, *py_hmac_compare_digest;
static PyObject *bytesio_ctor;

static const char *kHmacAlgos[] = {
  "md5", "sha224", "sha256", "sha384", "sha512", "sha3_256", "blake2s",
};
static constexpr int kNumHmacAlgos =
    sizeof(kHmacAlgos) / sizeof(kHmacAlgos[0]);

static const char *kPbkdf2Algos[] = {"sha1", "sha256", "sha512"};
static constexpr int kNumPbkdf2Algos = 3;

static const char *kHashlibAlgos[] = {"md5", "sha256", "sha3_256", "sha512"};
static constexpr int kNumHashlibAlgos = 4;

static unsigned long gc_counter = 0;

static int initialized = 0;

static void init_crypto(void) {
  if (initialized) return;

  struct {
    PyObject **dest;
    const char *mod, *attr;
  } inits[] = {
    {&ctor_md5, "_md5", "md5"},
    {&ctor_sha1, "_sha1", "sha1"},
    {&ctor_sha224, "_sha2", "sha224"},
    {&ctor_sha256, "_sha2", "sha256"},
    {&ctor_sha384, "_sha2", "sha384"},
    {&ctor_sha512, "_sha2", "sha512"},
    {&ctor_sha3_224, "_sha3", "sha3_224"},
    {&ctor_sha3_256, "_sha3", "sha3_256"},
    {&ctor_sha3_384, "_sha3", "sha3_384"},
    {&ctor_sha3_512, "_sha3", "sha3_512"},
    {&ctor_shake_128, "_sha3", "shake_128"},
    {&ctor_shake_256, "_sha3", "shake_256"},
    {&ctor_blake2b, "_blake2", "blake2b"},
    {&ctor_blake2s, "_blake2", "blake2s"},
  };
  for (auto &i : inits)
    *i.dest = import_attr(i.mod, i.attr);

  PyObject *hmac_mod = PyImport_ImportModule("_hmac");
  if (hmac_mod) {
    const char *names[] = {
      "compute_md5", "compute_sha1", "compute_sha256", "compute_sha512",
    };
    for (auto name : names) {
      PyObject *fn = PyObject_GetAttrString(hmac_mod, name);
      if (fn)
        hmac_compute_funcs[num_hmac_compute_funcs++] = fn;
      else
        PyErr_Clear();
    }
    Py_DECREF(hmac_mod);
  } else {
    PyErr_Clear();
  }

  hashlib_new = import_attr("hashlib", "new");
  hashlib_pbkdf2_hmac = import_attr("hashlib", "pbkdf2_hmac");
  hashlib_file_digest = import_attr("hashlib", "file_digest");
  py_hmac_new = import_attr("hmac", "new");
  py_hmac_digest = import_attr("hmac", "digest");
  py_hmac_compare_digest = import_attr("hmac", "compare_digest");
  bytesio_ctor = import_attr("io", "BytesIO");

  assert(!PyErr_Occurred());
  initialized = 1;
}

// ---------------------------------------------------------------------------
// Chained action loop — shared by OP_HASH_CHAIN, OP_SHAKE_CHAIN,
// OP_BLAKE2*_KEYED, OP_BLAKE2*_VARDIGEST, OP_PYHMAC_CHAIN, and
// OP_HASHLIB_CHAIN.
//
// Takes a borrowed reference to a hash-like object and loops up to 100
// fuzz-driven actions: .update(data), .digest(), .hexdigest(),
// .copy().digest(), and attribute reads (.name, .digest_size, .block_size).
// ---------------------------------------------------------------------------

static void chain_hash_actions(PyObject *h, FuzzedDataProvider &fdp) {
  for (int i = 0; fdp.remaining_bytes() > 0 && i < 100; i++) {
    switch (fdp.ConsumeIntegralInRange<int>(0, 4)) {
      case 0: {  // .update(data)
        std::string data = fdp.ConsumeBytesAsString(
            fdp.ConsumeIntegralInRange<size_t>(
                0, std::min(fdp.remaining_bytes(), (size_t)10000)));
        PyRef r = PyObject_CallMethod(h, "update", "y#", Y(data));
        CHECK(r);
        break;
      }
      case 1: {
        PyRef d = PyObject_CallMethod(h, "digest", NULL);
        CHECK(d);
        break;
      }
      case 2: {
        PyRef d = PyObject_CallMethod(h, "hexdigest", NULL);
        CHECK(d);
        break;
      }
      case 3: {  // .copy().digest()
        PyRef h2 = PyObject_CallMethod(h, "copy", NULL);
        CHECK(h2);
        PyRef d = PyObject_CallMethod(h2, "digest", NULL);
        CHECK(d);
        break;
      }
      case 4: {  // .name, .digest_size, .block_size
        PyRef n = PyObject_GetAttrString(h, "name");
        CHECK(n);
        PyRef ds = PyObject_GetAttrString(h, "digest_size");
        CHECK(ds);
        PyRef bs = PyObject_GetAttrString(h, "block_size");
        CHECK(bs);
        break;
      }
    }
  }
  if (PyErr_Occurred()) PyErr_Clear();
}

// ---------------------------------------------------------------------------
// Operations (13 ops).
// ---------------------------------------------------------------------------

// OP_HASH_CHAIN: Create a hash object from one of 12 C module constructors
// (_md5.md5, _sha1.sha1, _sha2.sha224/256/384/512, _sha3.sha3_224/256/384/512,
// _blake2.blake2b/s) with fuzz-chosen initial data, then run chained actions.
static void op_hash_chain(PyObject *ctor, FuzzedDataProvider &fdp) {
  std::string init = fdp.ConsumeBytesAsString(
      fdp.ConsumeIntegralInRange<size_t>(0, 10000));
  PyRef h = PyObject_CallFunction(ctor, "y#", Y(init));
  CHECK(h);
  chain_hash_actions(h, fdp);
}

// OP_SHAKE_CHAIN: Create a SHAKE-128 or SHAKE-256 XOF object, then loop
// up to 100 actions: .update(data), .digest(variable_length), or
// .copy().digest(variable_length). Exercises the variable-output-length
// code paths in _sha3.
static void op_shake_chain(PyObject *ctor, FuzzedDataProvider &fdp) {
  std::string init = fdp.ConsumeBytesAsString(
      fdp.ConsumeIntegralInRange<size_t>(0, 10000));
  PyRef h = PyObject_CallFunction(ctor, "y#", Y(init));
  CHECK(h);
  for (int i = 0; fdp.remaining_bytes() > 0 && i < 100; i++) {
    switch (fdp.ConsumeIntegralInRange<int>(0, 2)) {
      case 0: {
        std::string data = fdp.ConsumeBytesAsString(
            fdp.ConsumeIntegralInRange<size_t>(
                0, std::min(fdp.remaining_bytes(), (size_t)10000)));
        PyRef r = PyObject_CallMethod(h, "update", "y#", Y(data));
        CHECK(r);
        break;
      }
      case 1: {
        int len = fdp.ConsumeIntegralInRange<int>(1, 10000);
        PyRef d = PyObject_CallMethod(h, "digest", "i", len);
        CHECK(d);
        break;
      }
      case 2: {
        PyRef h2 = PyObject_CallMethod(h, "copy", NULL);
        CHECK(h2);
        int len = fdp.ConsumeIntegralInRange<int>(1, 10000);
        PyRef d = PyObject_CallMethod(h2, "digest", "i", len);
        CHECK(d);
        break;
      }
    }
  }
  if (PyErr_Occurred()) PyErr_Clear();
}

// OP_BLAKE2B_KEYED / OP_BLAKE2S_KEYED: Create a BLAKE2 object with
// fuzz-chosen key, salt, and person parameters (up to max_key/max_salt/
// max_person bytes respectively), then run chained hash actions.
// BLAKE2b: key<=64, salt<=16, person<=16. BLAKE2s: key<=32, salt<=8, person<=8.
static void op_blake2_keyed(PyObject *ctor, int max_key, int max_salt,
                            int max_person, FuzzedDataProvider &fdp) {
  std::string key = fdp.ConsumeBytesAsString(
      fdp.ConsumeIntegralInRange<size_t>(0, max_key));
  std::string salt = fdp.ConsumeBytesAsString(
      fdp.ConsumeIntegralInRange<size_t>(0, max_salt));
  std::string person = fdp.ConsumeBytesAsString(
      fdp.ConsumeIntegralInRange<size_t>(0, max_person));
  std::string data = fdp.ConsumeBytesAsString(
      fdp.ConsumeIntegralInRange<size_t>(0, 10000));

  PyRef kwargs = PyDict_New();
  CHECK(kwargs);
  PyRef k = PyBytes_FromStringAndSize(Y(key));
  CHECK(k);
  PyRef s = PyBytes_FromStringAndSize(Y(salt));
  CHECK(s);
  PyRef p = PyBytes_FromStringAndSize(Y(person));
  CHECK(p);
  PyDict_SetItemString(kwargs, "key", k);
  PyDict_SetItemString(kwargs, "salt", s);
  PyDict_SetItemString(kwargs, "person", p);

  PyRef d = PyBytes_FromStringAndSize(Y(data));
  CHECK(d);
  PyRef args = PyTuple_Pack(1, (PyObject *)d);
  CHECK(args);
  PyRef h = PyObject_Call(ctor, args, kwargs);
  CHECK(h);
  chain_hash_actions(h, fdp);
}

// OP_BLAKE2B_VARDIGEST / OP_BLAKE2S_VARDIGEST: Create a BLAKE2 object with
// a fuzz-chosen digest_size (1 to max_ds bytes), then run chained actions.
// Exercises the variable output length code path in _blake2.
static void op_blake2_vardigest(PyObject *ctor, int max_ds,
                                FuzzedDataProvider &fdp) {
  int ds = fdp.ConsumeIntegralInRange<int>(1, max_ds);
  std::string data = fdp.ConsumeBytesAsString(
      fdp.ConsumeIntegralInRange<size_t>(0, 10000));

  PyRef kwargs = PyDict_New();
  CHECK(kwargs);
  PyRef dsobj = PyLong_FromLong(ds);
  CHECK(dsobj);
  PyDict_SetItemString(kwargs, "digest_size", dsobj);

  PyRef d = PyBytes_FromStringAndSize(Y(data));
  CHECK(d);
  PyRef args = PyTuple_Pack(1, (PyObject *)d);
  CHECK(args);
  PyRef h = PyObject_Call(ctor, args, kwargs);
  CHECK(h);
  chain_hash_actions(h, fdp);
}

// OP_HMAC_COMPUTE: One-shot call to one of _hmac.compute_md5/sha1/sha256/sha512
// with fuzz-chosen key and message. These are the low-level C implementations
// of HMAC in the _hmac module (not the Python hmac wrapper).
static void op_hmac_compute(PyObject *func, FuzzedDataProvider &fdp) {
  std::string key = fdp.ConsumeBytesAsString(
      fdp.ConsumeIntegralInRange<size_t>(1, 10000));
  if (key.empty()) key.push_back('\x00');
  std::string msg = fdp.ConsumeRemainingBytesAsString();
  PyRef r = PyObject_CallFunction(func, "y#y#", Y(key), Y(msg));
  if (PyErr_Occurred()) PyErr_Clear();
}

// OP_PYHMAC_CHAIN: Create an HMAC object via hmac.new(key, digestmod=algo)
// where algo is fuzz-chosen from {md5, sha224, sha256, sha384, sha512,
// sha3_256, blake2s}, then run chained hash actions (update/digest/copy/etc).
// Exercises the Python hmac module which delegates to C hash constructors.
static void op_pyhmac_chain(const char *algo, FuzzedDataProvider &fdp) {
  std::string key = fdp.ConsumeBytesAsString(
      fdp.ConsumeIntegralInRange<size_t>(1, 10000));
  if (key.empty()) key.push_back('\x00');

  PyRef kwargs = PyDict_New();
  CHECK(kwargs);
  PyRef dm = PyUnicode_FromString(algo);
  CHECK(dm);
  PyDict_SetItemString(kwargs, "digestmod", dm);
  PyRef kb = PyBytes_FromStringAndSize(Y(key));
  CHECK(kb);
  PyRef args = PyTuple_Pack(1, (PyObject *)kb);
  CHECK(args);
  PyRef h = PyObject_Call(py_hmac_new, args, kwargs);
  CHECK(h);
  chain_hash_actions(h, fdp);
}

// OP_HMAC_DIGEST: One-shot call to hmac.digest(key, msg, "sha256").
// Exercises the fast single-call HMAC path without creating an HMAC object.
static void op_hmac_digest(FuzzedDataProvider &fdp) {
  std::string key = fdp.ConsumeBytesAsString(
      fdp.ConsumeIntegralInRange<size_t>(1, 10000));
  if (key.empty()) key.push_back('\x00');
  std::string msg = fdp.ConsumeRemainingBytesAsString();
  PyRef r = PyObject_CallFunction(py_hmac_digest, "y#y#s",
                                  Y(key), Y(msg), "sha256");
  if (PyErr_Occurred()) PyErr_Clear();
}

// OP_HMAC_COMPARE: Compute HMAC-SHA256 of fuzz data, then call
// hmac.compare_digest() against a zero-padded 32-byte buffer derived from
// the same data. Exercises the constant-time comparison code path.
static void op_hmac_compare(FuzzedDataProvider &fdp) {
  std::string data = fdp.ConsumeRemainingBytesAsString();
  PyRef h = PyObject_CallFunction(py_hmac_new, "sy#s",
                                  "k", Y(data), "sha256");
  CHECK(h);
  PyRef dig = PyObject_CallMethod(h, "digest", NULL);
  CHECK(dig);
  char padded[32] = {};
  memcpy(padded, data.data(), data.size() < 32 ? data.size() : 32);
  PyRef padobj = PyBytes_FromStringAndSize(padded, 32);
  CHECK(padobj);
  PyRef r = PyObject_CallFunction(py_hmac_compare_digest, "OO",
                                  (PyObject *)dig, (PyObject *)padobj);
  if (PyErr_Occurred()) PyErr_Clear();
}

// OP_HASHLIB_CHAIN: Create a hash object via hashlib.new(algo, data,
// usedforsecurity=False) where algo is fuzz-chosen from {md5, sha256,
// sha3_256, sha512}, then run chained actions. Unlike OP_HASH_CHAIN which
// uses the C module constructors directly, this goes through hashlib's
// dispatch logic (OpenSSL vs builtin).
static void op_hashlib_chain(const char *algo, FuzzedDataProvider &fdp) {
  std::string init = fdp.ConsumeBytesAsString(
      fdp.ConsumeIntegralInRange<size_t>(0, 10000));
  PyRef kwargs = PyDict_New();
  CHECK(kwargs);
  PyDict_SetItemString(kwargs, "usedforsecurity", Py_False);
  PyRef name = PyUnicode_FromString(algo);
  CHECK(name);
  PyRef d = PyBytes_FromStringAndSize(Y(init));
  CHECK(d);
  PyRef args = PyTuple_Pack(2, (PyObject *)name, (PyObject *)d);
  CHECK(args);
  PyRef h = PyObject_Call(hashlib_new, args, kwargs);
  CHECK(h);
  chain_hash_actions(h, fdp);
}

// OP_HASHLIB_FILE_DIGEST: One-shot call to hashlib.file_digest(BytesIO(data),
// algo) with fuzz-chosen algorithm, then .hexdigest(). Exercises the
// file-based hashing path that reads from a file-like object.
static void op_hashlib_file_digest(const char *algo, FuzzedDataProvider &fdp) {
  std::string data = fdp.ConsumeRemainingBytesAsString();
  PyRef bio = PyObject_CallFunction(bytesio_ctor, "y#", Y(data));
  CHECK(bio);
  PyRef h = PyObject_CallFunction(hashlib_file_digest, "Os",
                                  (PyObject *)bio, algo);
  CHECK(h);
  PyRef r = PyObject_CallMethod(h, "hexdigest", NULL);
  if (PyErr_Occurred()) PyErr_Clear();
}

// OP_PBKDF2: One-shot call to hashlib.pbkdf2_hmac(algo, password, salt, 1)
// with fuzz-chosen algorithm from {sha1, sha256, sha512}. Uses 1 iteration
// to keep execution fast while still exercising the PBKDF2 code path.
static void op_pbkdf2(const char *algo, FuzzedDataProvider &fdp) {
  std::string salt = fdp.ConsumeBytesAsString(
      fdp.ConsumeIntegralInRange<size_t>(1, 10000));
  if (salt.empty()) salt.push_back('\x00');
  std::string pw = fdp.ConsumeRemainingBytesAsString();
  PyRef r = PyObject_CallFunction(hashlib_pbkdf2_hmac, "sy#y#i",
                                  algo, Y(pw), Y(salt), 1);
  if (PyErr_Occurred()) PyErr_Clear();
}

// ---------------------------------------------------------------------------
// Dispatch.
// ---------------------------------------------------------------------------

enum Op {
  OP_HASH_CHAIN,
  OP_SHAKE_CHAIN,
  OP_BLAKE2B_KEYED,
  OP_BLAKE2S_KEYED,
  OP_BLAKE2B_VARDIGEST,
  OP_BLAKE2S_VARDIGEST,
  OP_HMAC_COMPUTE,
  OP_PYHMAC_CHAIN,
  OP_HMAC_DIGEST,
  OP_HMAC_COMPARE,
  OP_HASHLIB_CHAIN,
  OP_HASHLIB_FILE_DIGEST,
  OP_PBKDF2,
  NUM_OPS
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  assert(Py_IsInitialized());
  init_crypto();
  if (size < 1 || size > kMaxInputSize) return 0;
  if (PyErr_Occurred()) PyErr_Clear();

  FuzzedDataProvider fdp(data, size);
  switch (fdp.ConsumeIntegralInRange<int>(0, NUM_OPS - 1)) {
    case OP_HASH_CHAIN: {
      int ci = fdp.ConsumeIntegralInRange<int>(0, kNumHashCtors - 1);
      op_hash_chain(*all_hash_ctors[ci], fdp);
      break;
    }
    case OP_SHAKE_CHAIN: {
      int ci = fdp.ConsumeIntegralInRange<int>(0, kNumShakeCtors - 1);
      op_shake_chain(*shake_ctors[ci], fdp);
      break;
    }
    case OP_BLAKE2B_KEYED:
      op_blake2_keyed(ctor_blake2b, 64, 16, 16, fdp);
      break;
    case OP_BLAKE2S_KEYED:
      op_blake2_keyed(ctor_blake2s, 32, 8, 8, fdp);
      break;
    case OP_BLAKE2B_VARDIGEST:
      op_blake2_vardigest(ctor_blake2b, 64, fdp);
      break;
    case OP_BLAKE2S_VARDIGEST:
      op_blake2_vardigest(ctor_blake2s, 32, fdp);
      break;
    case OP_HMAC_COMPUTE:
      if (num_hmac_compute_funcs > 0) {
        int fi = fdp.ConsumeIntegralInRange<int>(
            0, num_hmac_compute_funcs - 1);
        op_hmac_compute(hmac_compute_funcs[fi], fdp);
      }
      break;
    case OP_PYHMAC_CHAIN: {
      int ai = fdp.ConsumeIntegralInRange<int>(0, kNumHmacAlgos - 1);
      op_pyhmac_chain(kHmacAlgos[ai], fdp);
      break;
    }
    case OP_HMAC_DIGEST:
      op_hmac_digest(fdp);
      break;
    case OP_HMAC_COMPARE:
      op_hmac_compare(fdp);
      break;
    case OP_HASHLIB_CHAIN: {
      int ai = fdp.ConsumeIntegralInRange<int>(0, kNumHashlibAlgos - 1);
      op_hashlib_chain(kHashlibAlgos[ai], fdp);
      break;
    }
    case OP_HASHLIB_FILE_DIGEST: {
      int ai = fdp.ConsumeIntegralInRange<int>(0, kNumHashlibAlgos - 1);
      op_hashlib_file_digest(kHashlibAlgos[ai], fdp);
      break;
    }
    case OP_PBKDF2: {
      int ai = fdp.ConsumeIntegralInRange<int>(0, kNumPbkdf2Algos - 1);
      op_pbkdf2(kPbkdf2Algos[ai], fdp);
      break;
    }
  }

  if (++gc_counter % kGcInterval == 0) PyGC_Collect();
  return 0;
}
