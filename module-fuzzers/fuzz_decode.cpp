// fuzz_decode.cpp — Fuzzer for CPython's compression, encoding, serialization,
// and certificate-parsing C extension modules.
//
// This fuzzer exercises the following CPython C extension modules via
// their Python API, called through the Python C API from C++:
//
//   zlib               — compress/decompress (one-shot and streaming via
//                         compressobj/decompressobj with wbits, zdict, copy,
//                         flush), crc32, adler32
//   _bz2               — BZ2Decompressor.decompress(), bz2.compress()
//   _lzma              — LZMADecompressor.decompress() with FORMAT_AUTO/XZ/ALONE
//                         and 16 MB memlimit, lzma.compress()
//   binascii           — 6 decoders: a2b_base64 (with strict_mode), a2b_hex,
//                         a2b_uu, a2b_qp, a2b_ascii85, a2b_base85
//                         6 encoders: b2a_base64 (with newline), b2a_hex,
//                         b2a_uu (clamped to 45 bytes), b2a_qp,
//                         b2a_ascii85 (with foldspaces/wrapcol), b2a_base85
//                         Checksums: crc32, crc_hqx
//                         Round-trip: hexlify -> unhexlify
//   _pickle             — pickle.dumps() with 8 container types (bytes, str,
//                         list, tuple, set, frozenset, bytearray, dict) across
//                         protocols 0-5 and fix_imports flag.
//                         pickle.loads() via RestrictedUnpickler (blocks
//                         find_class), PersistentUnpickler (handles PERSID/
//                         BINPERSID), and RestrictedUnpickler with
//                         encoding='bytes'.
//                         Pickler chain: dump, clear_memo, dump, getvalue.
//                         Round-trip: dumps then loads.
//   _ssl               — ssl.DER_cert_to_PEM_cert(), then optionally
//                         SSLContext(PROTOCOL_TLS_CLIENT).load_verify_locations()
//   _multibytecodec,
//   _codecs_jp, _codecs_cn, _codecs_kr,
//   _codecs_hk, _codecs_tw, _codecs_iso2022
//                       — codecs.decode() with 17 codecs including shift_jis,
//                         euc-jp, gb2312, big5, gb18030, iso-2022-jp, etc.
//                         codecs.encode() with 19 codecs.
//                         Incremental decoders (shift_jis, gb18030, utf-16):
//                         split input at midpoint, decode halves, getstate, reset.
//                         Incremental encoders (shift_jis, utf-8):
//                         split string at midpoint, encode, reset, getstate.
//                         StreamReader: codecs.getreader('utf-8')(BytesIO).read()
//
// The first byte of fuzz input selects one of 20 operation types. Each
// operation consumes further bytes via FuzzedDataProvider to parameterize
// the call (algorithm/codec selection, compression level, protocol number,
// container type, wbits value, boolean flags, data splits).
//
// All module functions, constructors, and format constants are imported once
// during init and cached as static PyObject* and long pointers. Two pickle
// Unpickler subclasses (RestrictedUnpickler, PersistentUnpickler) are defined
// via PyRun_String at init time and cached as class objects.
//
// PyRef (RAII) prevents reference leaks. PyGC_Collect() runs every 200
// iterations. Max input size: 1 MB.

#include "fuzz_helpers.h"

// ---------------------------------------------------------------------------
// Cached module objects, initialized once.
// ---------------------------------------------------------------------------

// zlib
static PyObject *zlib_compress, *zlib_decompress;
static PyObject *zlib_decompressobj, *zlib_compressobj;
static PyObject *zlib_crc32, *zlib_adler32;

// bz2
static PyObject *bz2_compress, *bz2_BZ2Decompressor;

// lzma
static PyObject *lzma_LZMADecompressor, *lzma_compress;
static long lzma_FORMAT_AUTO_val, lzma_FORMAT_XZ_val, lzma_FORMAT_ALONE_val;

// binascii
static PyObject *ba_a2b_base64, *ba_a2b_hex, *ba_a2b_uu, *ba_a2b_qp;
static PyObject *ba_a2b_ascii85, *ba_a2b_base85;
static PyObject *ba_b2a_base64, *ba_b2a_hex, *ba_b2a_uu, *ba_b2a_qp;
static PyObject *ba_b2a_ascii85, *ba_b2a_base85;
static PyObject *ba_crc32, *ba_crc_hqx, *ba_hexlify, *ba_unhexlify;

// pickle
static PyObject *pickle_dumps, *pickle_loads;

// codecs
static PyObject *codecs_decode, *codecs_encode;
static PyObject *codecs_getincrementaldecoder, *codecs_getincrementalencoder;
static PyObject *codecs_getreader;

// ssl
static PyObject *ssl_DER_cert_to_PEM_cert, *ssl_SSLContext;
static long ssl_PROTOCOL_TLS_CLIENT_val;

// io
static PyObject *bytesio_ctor;

// pickle helper classes
static PyObject *RestrictedUnpickler_cls, *PersistentUnpickler_cls;

static unsigned long gc_counter = 0;

static int initialized = 0;

static void init_decode(void) {
  if (initialized) return;

  // zlib
  zlib_compress = import_attr("zlib", "compress");
  zlib_decompress = import_attr("zlib", "decompress");
  zlib_decompressobj = import_attr("zlib", "decompressobj");
  zlib_compressobj = import_attr("zlib", "compressobj");
  zlib_crc32 = import_attr("zlib", "crc32");
  zlib_adler32 = import_attr("zlib", "adler32");

  // bz2
  bz2_compress = import_attr("bz2", "compress");
  bz2_BZ2Decompressor = import_attr("bz2", "BZ2Decompressor");

  // lzma
  lzma_LZMADecompressor = import_attr("lzma", "LZMADecompressor");
  lzma_compress = import_attr("lzma", "compress");
  {
    PyObject *v;
    v = import_attr("lzma", "FORMAT_AUTO");
    lzma_FORMAT_AUTO_val = PyLong_AsLong(v);
    Py_DECREF(v);
    v = import_attr("lzma", "FORMAT_XZ");
    lzma_FORMAT_XZ_val = PyLong_AsLong(v);
    Py_DECREF(v);
    v = import_attr("lzma", "FORMAT_ALONE");
    lzma_FORMAT_ALONE_val = PyLong_AsLong(v);
    Py_DECREF(v);
  }

  // binascii
  ba_a2b_base64 = import_attr("binascii", "a2b_base64");
  ba_a2b_hex = import_attr("binascii", "a2b_hex");
  ba_a2b_uu = import_attr("binascii", "a2b_uu");
  ba_a2b_qp = import_attr("binascii", "a2b_qp");
  ba_a2b_ascii85 = import_attr("binascii", "a2b_ascii85");
  ba_a2b_base85 = import_attr("binascii", "a2b_base85");
  ba_b2a_base64 = import_attr("binascii", "b2a_base64");
  ba_b2a_hex = import_attr("binascii", "b2a_hex");
  ba_b2a_uu = import_attr("binascii", "b2a_uu");
  ba_b2a_qp = import_attr("binascii", "b2a_qp");
  ba_b2a_ascii85 = import_attr("binascii", "b2a_ascii85");
  ba_b2a_base85 = import_attr("binascii", "b2a_base85");
  ba_crc32 = import_attr("binascii", "crc32");
  ba_crc_hqx = import_attr("binascii", "crc_hqx");
  ba_hexlify = import_attr("binascii", "hexlify");
  ba_unhexlify = import_attr("binascii", "unhexlify");

  // pickle
  pickle_dumps = import_attr("pickle", "dumps");
  pickle_loads = import_attr("pickle", "loads");

  // codecs
  codecs_decode = import_attr("codecs", "decode");
  codecs_encode = import_attr("codecs", "encode");
  codecs_getincrementaldecoder = import_attr("codecs",
                                             "getincrementaldecoder");
  codecs_getincrementalencoder = import_attr("codecs",
                                             "getincrementalencoder");
  codecs_getreader = import_attr("codecs", "getreader");

  // ssl
  ssl_DER_cert_to_PEM_cert = import_attr("ssl", "DER_cert_to_PEM_cert");
  ssl_SSLContext = import_attr("ssl", "SSLContext");
  {
    PyObject *v = import_attr("ssl", "PROTOCOL_TLS_CLIENT");
    ssl_PROTOCOL_TLS_CLIENT_val = PyLong_AsLong(v);
    Py_DECREF(v);
  }

  // io
  bytesio_ctor = import_attr("io", "BytesIO");

  // Suppress warnings.
  PyRun_SimpleString("import warnings; warnings.filterwarnings('ignore')");

  // Pickle helper classes via PyRun_String.
  {
    PyObject *globals = PyDict_New();
    PyDict_SetItemString(globals, "__builtins__", PyEval_GetBuiltins());
    PyObject *r = PyRun_String(
        "import pickle, io\n"
        "class RestrictedUnpickler(pickle.Unpickler):\n"
        "    def find_class(self, module, name):\n"
        "        raise pickle.UnpicklingError('restricted')\n"
        "class PersistentUnpickler(pickle.Unpickler):\n"
        "    def persistent_load(self, pid): return pid\n"
        "    def find_class(self, module, name):\n"
        "        raise pickle.UnpicklingError('restricted')\n",
        Py_file_input, globals, globals);
    if (!r) {
      PyErr_Print();
      abort();
    }
    Py_DECREF(r);
    RestrictedUnpickler_cls =
        PyDict_GetItemString(globals, "RestrictedUnpickler");
    Py_INCREF(RestrictedUnpickler_cls);
    PersistentUnpickler_cls =
        PyDict_GetItemString(globals, "PersistentUnpickler");
    Py_INCREF(PersistentUnpickler_cls);
    Py_DECREF(globals);
  }

  assert(!PyErr_Occurred());
  initialized = 1;
}

// ---------------------------------------------------------------------------
// Operations — Compression (6 ops)
// ---------------------------------------------------------------------------

// OP_ZLIB_DECOMPRESS: Create a zlib.decompressobj with fuzz-chosen wbits
// from {-15 (raw), 0 (auto), 15 (zlib), 31 (gzip), 47 (auto-detect)} and
// an optional zdict (first 32 bytes of data). Call .decompress(data, 1MB),
// optionally .flush(), and optionally .copy() + decompress on the copy.
// Exercises Decomp_Type, zlib_Decompress_decompress, copy, flush paths.
static void op_zlib_decompress(FuzzedDataProvider &fdp) {
  static const int kWbitsChoices[] = {-15, 0, 15, 31, 47};
  int wbits = kWbitsChoices[fdp.ConsumeIntegralInRange<int>(0, 4)];
  bool use_zdict = fdp.ConsumeBool();
  std::string data = fdp.ConsumeRemainingBytesAsString();

  PyRef kwargs = PyDict_New();
  CHECK(kwargs);
  PyRef wbits_obj = PyLong_FromLong(wbits);
  CHECK(wbits_obj);
  PyRef args_dobj = PyTuple_Pack(1, (PyObject *)wbits_obj);
  CHECK(args_dobj);

  if (use_zdict && data.size() > 32) {
    PyRef zdict = PyBytes_FromStringAndSize(data.data(), 32);
    CHECK(zdict);
    PyDict_SetItemString(kwargs, "zdict", zdict);
    data = data.substr(32);
  }

  PyRef dobj = PyObject_Call(zlib_decompressobj, args_dobj, kwargs);
  CHECK(dobj);

  PyRef pydata = PyBytes_FromStringAndSize(Y(data));
  CHECK(pydata);
  PyRef r = PyObject_CallMethod(dobj, "decompress", "Oi",
                                (PyObject *)pydata, 1048576);
  if (!r) {
    PyErr_Clear();
    return;
  }

  if (fdp.remaining_bytes() > 0 || data.size() % 2 == 0) {
    PyRef flush_r = PyObject_CallMethod(dobj, "flush", NULL);
    if (PyErr_Occurred()) PyErr_Clear();
  }

  if (data.size() % 3 == 0) {
    PyRef copy_obj = PyObject_CallMethod(dobj, "copy", NULL);
    if (copy_obj) {
      PyRef r2 = PyObject_CallMethod(copy_obj, "decompress", "Oi",
                                     (PyObject *)pydata, 1048576);
      if (PyErr_Occurred()) PyErr_Clear();
    } else {
      PyErr_Clear();
    }
  }
}

// OP_ZLIB_COMPRESS: Either one-shot zlib.compress(data, level) or streaming
// via compressobj(level).compress(data).flush(), with optional .copy().flush().
// Level is fuzz-chosen 0-9. Exercises Compress_Type and zlib_compress_impl.
static void op_zlib_compress(FuzzedDataProvider &fdp) {
  int level = fdp.ConsumeIntegralInRange<int>(0, 9);
  bool use_obj = fdp.ConsumeBool();
  std::string data = fdp.ConsumeBytesAsString(
      std::min(fdp.remaining_bytes(), (size_t)10000));

  PyRef pydata = PyBytes_FromStringAndSize(Y(data));
  CHECK(pydata);

  if (use_obj) {
    PyRef cobj = PyObject_CallFunction(zlib_compressobj, "i", level);
    CHECK(cobj);
    PyRef r1 = PyObject_CallMethod(cobj, "compress", "O",
                                   (PyObject *)pydata);
    CHECK(r1);
    if (data.size() % 2 == 0) {
      PyRef copy_obj = PyObject_CallMethod(cobj, "copy", NULL);
      if (copy_obj) {
        PyRef r2 = PyObject_CallMethod(copy_obj, "flush", NULL);
        if (PyErr_Occurred()) PyErr_Clear();
      } else {
        PyErr_Clear();
      }
    }
    PyRef r3 = PyObject_CallMethod(cobj, "flush", NULL);
    if (PyErr_Occurred()) PyErr_Clear();
  } else {
    PyRef r = PyObject_CallFunction(zlib_compress, "Oi",
                                    (PyObject *)pydata, level);
    if (PyErr_Occurred()) PyErr_Clear();
  }
}

// OP_ZLIB_CHECKSUM: Call either zlib.crc32(data) or zlib.adler32(data),
// fuzz-chosen. Exercises the checksum C implementations in zlibmodule.c.
static void op_zlib_checksum(FuzzedDataProvider &fdp) {
  bool use_crc = fdp.ConsumeBool();
  std::string data = fdp.ConsumeRemainingBytesAsString();
  PyRef pydata = PyBytes_FromStringAndSize(Y(data));
  CHECK(pydata);
  PyRef r = PyObject_CallFunction(
      use_crc ? zlib_crc32 : zlib_adler32, "O", (PyObject *)pydata);
  if (PyErr_Occurred()) PyErr_Clear();
}

// OP_BZ2: Either bz2.compress(data) or BZ2Decompressor().decompress(data, 1MB),
// fuzz-chosen. Exercises the _bz2 C extension (BZ2Compressor/BZ2Decompressor).
static void op_bz2(FuzzedDataProvider &fdp) {
  bool do_compress = fdp.ConsumeBool();
  std::string data = fdp.ConsumeBytesAsString(
      std::min(fdp.remaining_bytes(), (size_t)10000));
  PyRef pydata = PyBytes_FromStringAndSize(Y(data));
  CHECK(pydata);

  if (do_compress) {
    PyRef r = PyObject_CallFunction(bz2_compress, "O",
                                    (PyObject *)pydata);
    if (PyErr_Occurred()) PyErr_Clear();
  } else {
    PyRef dobj = PyObject_CallFunction(bz2_BZ2Decompressor, NULL);
    CHECK(dobj);
    PyRef r = PyObject_CallMethod(dobj, "decompress", "Oi",
                                  (PyObject *)pydata, 1048576);
    if (PyErr_Occurred()) PyErr_Clear();
  }
}

// OP_LZMA_DECOMPRESS: Create LZMADecompressor with fuzz-chosen format from
// {FORMAT_AUTO, FORMAT_XZ, FORMAT_ALONE} and 16 MB memlimit, then call
// .decompress(data, 1MB). Exercises the _lzma C extension decompressor.
static void op_lzma_decompress(FuzzedDataProvider &fdp) {
  long fmt_vals[] = {
    lzma_FORMAT_AUTO_val, lzma_FORMAT_XZ_val, lzma_FORMAT_ALONE_val,
  };
  long fmt = fmt_vals[fdp.ConsumeIntegralInRange<int>(0, 2)];
  std::string data = fdp.ConsumeBytesAsString(
      std::min(fdp.remaining_bytes(), (size_t)10000));
  PyRef pydata = PyBytes_FromStringAndSize(Y(data));
  CHECK(pydata);

  PyRef kwargs = PyDict_New();
  CHECK(kwargs);
  PyRef fmt_obj = PyLong_FromLong(fmt);
  CHECK(fmt_obj);
  PyDict_SetItemString(kwargs, "format", fmt_obj);
  PyRef memlimit = PyLong_FromLong(16 * 1024 * 1024);
  CHECK(memlimit);
  PyDict_SetItemString(kwargs, "memlimit", memlimit);

  PyRef empty_args = PyTuple_New(0);
  CHECK(empty_args);
  PyRef dobj = PyObject_Call(lzma_LZMADecompressor, empty_args, kwargs);
  CHECK(dobj);

  PyRef r = PyObject_CallMethod(dobj, "decompress", "Oi",
                                (PyObject *)pydata, 1048576);
  if (PyErr_Occurred()) PyErr_Clear();
}

// OP_LZMA_COMPRESS: One-shot lzma.compress(data). Exercises the _lzma
// C extension compressor with default settings.
static void op_lzma_compress(FuzzedDataProvider &fdp) {
  std::string data = fdp.ConsumeBytesAsString(
      std::min(fdp.remaining_bytes(), (size_t)10000));
  PyRef pydata = PyBytes_FromStringAndSize(Y(data));
  CHECK(pydata);
  PyRef r = PyObject_CallFunction(lzma_compress, "O", (PyObject *)pydata);
  if (PyErr_Occurred()) PyErr_Clear();
}

// ---------------------------------------------------------------------------
// Operations — Binascii (4 ops)
// ---------------------------------------------------------------------------

// OP_BINASCII_DECODE: Call one of 6 binary-to-binary decoders from the
// binascii C module: a2b_base64 (with optional strict_mode=True), a2b_hex,
// a2b_uu, a2b_qp, a2b_ascii85, a2b_base85. Fuzz selects which decoder.
static void op_binascii_decode(FuzzedDataProvider &fdp) {
  int which = fdp.ConsumeIntegralInRange<int>(0, 5);
  bool strict = fdp.ConsumeBool();
  std::string data = fdp.ConsumeRemainingBytesAsString();
  PyRef pydata = PyBytes_FromStringAndSize(Y(data));
  CHECK(pydata);

  PyObject *funcs[] = {
    ba_a2b_base64, ba_a2b_hex, ba_a2b_uu,
    ba_a2b_qp, ba_a2b_ascii85, ba_a2b_base85,
  };

  if (which == 0 && strict) {
    PyRef kwargs = PyDict_New();
    CHECK(kwargs);
    PyDict_SetItemString(kwargs, "strict_mode", Py_True);
    PyRef args = PyTuple_Pack(1, (PyObject *)pydata);
    CHECK(args);
    PyRef r = PyObject_Call(ba_a2b_base64, args, kwargs);
  } else {
    PyRef r = PyObject_CallFunction(funcs[which], "O",
                                    (PyObject *)pydata);
  }
  if (PyErr_Occurred()) PyErr_Clear();
}

// OP_BINASCII_ENCODE: Call one of 6 binary-to-text encoders from the
// binascii C module: b2a_base64 (with optional newline kwarg), b2a_hex,
// b2a_uu (input clamped to 45 bytes), b2a_qp, b2a_ascii85 (with optional
// foldspaces and wrapcol=72), b2a_base85. Fuzz selects which encoder.
static void op_binascii_encode(FuzzedDataProvider &fdp) {
  int which = fdp.ConsumeIntegralInRange<int>(0, 5);
  std::string data = fdp.ConsumeBytesAsString(
      std::min(fdp.remaining_bytes(), (size_t)10000));

  // b2a_uu requires <= 45 bytes.
  if (which == 2 && data.size() > 45) data.resize(45);

  PyRef pydata = PyBytes_FromStringAndSize(Y(data));
  CHECK(pydata);

  PyObject *funcs[] = {
    ba_b2a_base64, ba_b2a_hex, ba_b2a_uu,
    ba_b2a_qp, ba_b2a_ascii85, ba_b2a_base85,
  };

  if (which == 0) {
    // b2a_base64 with optional newline kwarg.
    bool newline = fdp.ConsumeBool();
    PyRef kwargs = PyDict_New();
    CHECK(kwargs);
    PyDict_SetItemString(kwargs, "newline", newline ? Py_True : Py_False);
    PyRef args = PyTuple_Pack(1, (PyObject *)pydata);
    CHECK(args);
    PyRef r = PyObject_Call(ba_b2a_base64, args, kwargs);
  } else if (which == 4) {
    // b2a_ascii85 with optional foldspaces/wrapcol.
    bool foldspaces = fdp.ConsumeBool();
    PyRef kwargs = PyDict_New();
    CHECK(kwargs);
    if (foldspaces)
      PyDict_SetItemString(kwargs, "foldspaces", Py_True);
    PyRef wrapcol = PyLong_FromLong(72);
    CHECK(wrapcol);
    PyDict_SetItemString(kwargs, "wrapcol", wrapcol);
    PyRef args = PyTuple_Pack(1, (PyObject *)pydata);
    CHECK(args);
    PyRef r = PyObject_Call(ba_b2a_ascii85, args, kwargs);
  } else {
    PyRef r = PyObject_CallFunction(funcs[which], "O",
                                    (PyObject *)pydata);
  }
  if (PyErr_Occurred()) PyErr_Clear();
}

// OP_BINASCII_CHECKSUM: Call either binascii.crc32(data) or
// binascii.crc_hqx(data, 0), fuzz-chosen.
static void op_binascii_checksum(FuzzedDataProvider &fdp) {
  bool use_crc32 = fdp.ConsumeBool();
  std::string data = fdp.ConsumeRemainingBytesAsString();
  PyRef pydata = PyBytes_FromStringAndSize(Y(data));
  CHECK(pydata);

  if (use_crc32) {
    PyRef r = PyObject_CallFunction(ba_crc32, "O", (PyObject *)pydata);
  } else {
    PyRef r = PyObject_CallFunction(ba_crc_hqx, "Oi",
                                    (PyObject *)pydata, 0);
  }
  if (PyErr_Occurred()) PyErr_Clear();
}

// OP_BINASCII_ROUNDTRIP: binascii.hexlify(data) then binascii.unhexlify()
// on the result. Exercises both directions of hex encoding.
static void op_binascii_roundtrip(FuzzedDataProvider &fdp) {
  std::string data = fdp.ConsumeRemainingBytesAsString();
  PyRef pydata = PyBytes_FromStringAndSize(Y(data));
  CHECK(pydata);
  PyRef hexed = PyObject_CallFunction(ba_hexlify, "O",
                                      (PyObject *)pydata);
  CHECK(hexed);
  PyRef r = PyObject_CallFunction(ba_unhexlify, "O", (PyObject *)hexed);
  if (PyErr_Occurred()) PyErr_Clear();
}

// ---------------------------------------------------------------------------
// Operations — Pickle (4 ops)
// ---------------------------------------------------------------------------

// Build a Python container from fuzz bytes for pickle.dumps operations.
// type selects: 0=bytes, 1=str, 2=list of ints, 3=tuple of ints,
// 4=set of ints, 5=frozenset of ints, 6=bytearray, 7=dict(int->None).
// Capped at 256 elements to keep serialization fast.
// str_enc selects the byte-to-str decoding (see fuzz_bytes_to_str).
static PyObject *build_pickle_container(int type, const uint8_t *buf,
                                        size_t len, int str_enc) {
  if (len > 256) len = 256;
  switch (type) {
    case 0:  // raw bytes
      return PyBytes_FromStringAndSize((const char *)buf, len);
    case 1: {  // str
      std::string s((const char *)buf, len);
      return fuzz_bytes_to_str(s, str_enc);
    }
    case 2: {  // list of ints
      PyObject *lst = PyList_New((Py_ssize_t)len);
      if (!lst) return NULL;
      for (size_t i = 0; i < len; i++)
        PyList_SET_ITEM(lst, i, PyLong_FromLong(buf[i]));
      return lst;
    }
    case 3: {  // tuple of ints
      PyObject *tup = PyTuple_New((Py_ssize_t)len);
      if (!tup) return NULL;
      for (size_t i = 0; i < len; i++)
        PyTuple_SET_ITEM(tup, i, PyLong_FromLong(buf[i]));
      return tup;
    }
    case 4: {  // set
      PyObject *lst = PyList_New((Py_ssize_t)len);
      if (!lst) return NULL;
      for (size_t i = 0; i < len; i++)
        PyList_SET_ITEM(lst, i, PyLong_FromLong(buf[i]));
      PyObject *s = PySet_New(lst);
      Py_DECREF(lst);
      return s;
    }
    case 5: {  // frozenset
      PyObject *lst = PyList_New((Py_ssize_t)len);
      if (!lst) return NULL;
      for (size_t i = 0; i < len; i++)
        PyList_SET_ITEM(lst, i, PyLong_FromLong(buf[i]));
      PyObject *s = PyFrozenSet_New(lst);
      Py_DECREF(lst);
      return s;
    }
    case 6:  // bytearray
      return PyByteArray_FromStringAndSize((const char *)buf, len);
    case 7: {  // dict.fromkeys
      PyObject *d = PyDict_New();
      if (!d) return NULL;
      for (size_t i = 0; i < len; i++) {
        PyRef key = PyLong_FromLong(buf[i]);
        if (key) PyDict_SetItem(d, key, Py_None);
      }
      return d;
    }
    default:
      return PyBytes_FromStringAndSize((const char *)buf, len);
  }
}

// OP_PICKLE_DUMPS: Build a fuzz-chosen container type (see
// build_pickle_container; str containers use fuzz_bytes_to_str for
// fuzz-chosen byte-to-str decoding), then call pickle.dumps(obj, protocol=N,
// fix_imports=bool). Protocol is fuzz-chosen 0-5, exercising all pickle
// opcodes: MARK, SHORT_BINBYTES, BINUNICODE, EMPTY_SET, ADDITEMS,
// FROZENSET, BYTEARRAY8, SETITEMS, etc.
static void op_pickle_dumps(FuzzedDataProvider &fdp) {
  int container_type = fdp.ConsumeIntegralInRange<int>(0, 7);
  int protocol = fdp.ConsumeIntegralInRange<int>(0, 5);
  bool fix_imports = fdp.ConsumeBool();
  int str_enc = fdp.ConsumeIntegralInRange<int>(0, 3);
  std::string data = fdp.ConsumeBytesAsString(
      std::min(fdp.remaining_bytes(), (size_t)10000));

  PyRef obj(build_pickle_container(
      container_type, (const uint8_t *)data.data(), data.size(), str_enc));
  CHECK(obj);

  PyRef kwargs = PyDict_New();
  CHECK(kwargs);
  PyRef proto = PyLong_FromLong(protocol);
  CHECK(proto);
  PyDict_SetItemString(kwargs, "protocol", proto);
  PyDict_SetItemString(kwargs, "fix_imports",
                       fix_imports ? Py_True : Py_False);
  PyRef args = PyTuple_Pack(1, (PyObject *)obj);
  CHECK(args);
  PyRef r = PyObject_Call(pickle_dumps, args, kwargs);
  if (PyErr_Occurred()) PyErr_Clear();
}

// OP_PICKLE_LOADS: Wrap fuzz data in BytesIO, then unpickle via one of 3
// Unpickler subclass variants (fuzz-chosen):
//   0 — RestrictedUnpickler: blocks find_class (safe against arbitrary code)
//   1 — PersistentUnpickler: handles PERSID/BINPERSID opcodes, blocks find_class
//   2 — RestrictedUnpickler with fix_imports=True, encoding='bytes' (Py2 compat)
// Exercises the _pickle C extension's Unpickler_Type code paths.
static void op_pickle_loads(FuzzedDataProvider &fdp) {
  int variant = fdp.ConsumeIntegralInRange<int>(0, 2);
  std::string data = fdp.ConsumeRemainingBytesAsString();
  PyRef pydata = PyBytes_FromStringAndSize(Y(data));
  CHECK(pydata);
  PyRef bio = PyObject_CallFunction(bytesio_ctor, "O",
                                    (PyObject *)pydata);
  CHECK(bio);

  PyObject *cls = nullptr;
  PyRef kwargs_ref;
  switch (variant) {
    case 0:  // RestrictedUnpickler
      cls = RestrictedUnpickler_cls;
      break;
    case 1:  // PersistentUnpickler
      cls = PersistentUnpickler_cls;
      break;
    case 2: {  // RestrictedUnpickler with fix_imports + encoding='bytes'
      cls = RestrictedUnpickler_cls;
      kwargs_ref = PyRef(PyDict_New());
      CHECK(kwargs_ref);
      PyDict_SetItemString(kwargs_ref, "fix_imports", Py_True);
      PyRef enc = PyUnicode_FromString("bytes");
      CHECK(enc);
      PyDict_SetItemString(kwargs_ref, "encoding", enc);
      break;
    }
  }

  PyRef args = PyTuple_Pack(1, (PyObject *)bio);
  CHECK(args);
  PyRef unpickler = PyObject_Call(
      cls, args, kwargs_ref.p ? (PyObject *)kwargs_ref : NULL);
  CHECK(unpickler);
  PyRef r = PyObject_CallMethod(unpickler, "load", NULL);
  if (PyErr_Occurred()) PyErr_Clear();
}

// OP_PICKLE_PICKLER: Create pickle.Pickler(BytesIO, protocol=N), then chain:
// .dump(list_of_ints), .clear_memo(), .dump(str), .getvalue().
// The str object for the second dump is built via fuzz_bytes_to_str with a
// fuzz-chosen decoding. Exercises the Pickler_Type, memo proxy clear, and
// multi-dump sequences in the _pickle C extension. Protocol is fuzz-chosen 0-5.
static void op_pickle_pickler(FuzzedDataProvider &fdp) {
  int protocol = fdp.ConsumeIntegralInRange<int>(0, 5);
  int str_enc = fdp.ConsumeIntegralInRange<int>(0, 3);
  std::string data = fdp.ConsumeBytesAsString(
      std::min(fdp.remaining_bytes(), (size_t)10000));

  PyRef bio = PyObject_CallFunction(bytesio_ctor, NULL);
  CHECK(bio);

  // Import pickle.Pickler (cached after first call).
  static PyObject *pickle_Pickler = nullptr;
  if (!pickle_Pickler) {
    pickle_Pickler = import_attr("pickle", "Pickler");
  }

  PyRef pickler = PyObject_CallFunction(pickle_Pickler, "Oi",
                                        (PyObject *)bio, protocol);
  CHECK(pickler);

  // Build first object: list of ints.
  PyRef obj1(build_pickle_container(
      2, (const uint8_t *)data.data(), data.size(), str_enc));
  CHECK(obj1);

  PyRef r1 = PyObject_CallMethod(pickler, "dump", "O", (PyObject *)obj1);
  if (!r1) {
    PyErr_Clear();
    return;
  }

  PyRef cm = PyObject_CallMethod(pickler, "clear_memo", NULL);
  if (PyErr_Occurred()) PyErr_Clear();

  // Build second object: string.
  PyRef obj2(fuzz_bytes_to_str(data, str_enc));
  CHECK(obj2);
  PyRef r2 = PyObject_CallMethod(pickler, "dump", "O", (PyObject *)obj2);
  if (PyErr_Occurred()) PyErr_Clear();

  PyRef val = PyObject_CallMethod(bio, "getvalue", NULL);
  if (PyErr_Occurred()) PyErr_Clear();
}

// OP_PICKLE_ROUNDTRIP: Build a fuzz-chosen container (str containers use
// fuzz_bytes_to_str for fuzz-chosen byte-to-str decoding), pickle.dumps() it,
// then pickle.loads() the result. Exercises both Pickler and Unpickler in
// a single iteration, ensuring round-trip consistency.
static void op_pickle_roundtrip(FuzzedDataProvider &fdp) {
  int container_type = fdp.ConsumeIntegralInRange<int>(0, 7);
  int str_enc = fdp.ConsumeIntegralInRange<int>(0, 3);
  std::string data = fdp.ConsumeBytesAsString(
      std::min(fdp.remaining_bytes(), (size_t)10000));

  PyRef obj(build_pickle_container(
      container_type, (const uint8_t *)data.data(), data.size(), str_enc));
  CHECK(obj);

  PyRef dumped = PyObject_CallFunction(pickle_dumps, "O", (PyObject *)obj);
  if (!dumped) {
    PyErr_Clear();
    return;
  }
  PyRef loaded = PyObject_CallFunction(pickle_loads, "O",
                                       (PyObject *)dumped);
  if (PyErr_Occurred()) PyErr_Clear();
}

// ---------------------------------------------------------------------------
// Operations — Codecs (5 ops)
//
// These exercise the _multibytecodec C engine and per-language codec
// C modules (_codecs_jp, _codecs_cn, _codecs_kr, _codecs_hk, _codecs_tw,
// _codecs_iso2022) as well as built-in codecs (utf-7/8/16/32, ascii,
// latin-1, charmap, unicode_escape, raw_unicode_escape, cp1252).
// ---------------------------------------------------------------------------

// Codec names for OP_CODECS_DECODE: 17 decoders covering multibyte CJK
// codecs plus single-byte and Unicode escape codecs.
static const char *kCodecDecoders[] = {
  "utf-7", "shift_jis", "euc-jp", "gb2312", "big5", "iso-2022-jp",
  "euc-kr", "gb18030", "big5hkscs", "charmap", "ascii", "latin-1",
  "cp1252", "unicode_escape", "raw_unicode_escape", "utf-16", "utf-32",
};
static constexpr int kNumCodecDecoders =
    sizeof(kCodecDecoders) / sizeof(kCodecDecoders[0]);

// Codec names for OP_CODECS_ENCODE: 19 encoders covering multibyte CJK
// codecs plus Unicode, UTF, and single-byte encoders.
static const char *kCodecEncoders[] = {
  "shift_jis", "euc-jp", "gb2312", "big5", "iso-2022-jp", "euc-kr",
  "gb18030", "big5hkscs", "unicode_escape", "raw_unicode_escape",
  "utf-7", "utf-8", "utf-16", "utf-16-le", "utf-16-be", "utf-32",
  "latin-1", "ascii", "charmap",
};
static constexpr int kNumCodecEncoders =
    sizeof(kCodecEncoders) / sizeof(kCodecEncoders[0]);

// OP_CODECS_DECODE: Call codecs.decode(bytes, codec, 'replace') with a
// fuzz-chosen codec from 17 decoders. The 'replace' error handler ensures
// no UnicodeDecodeError is raised. Exercises the multibytecodec_decode and
// built-in codec decode paths.
static void op_codecs_decode(FuzzedDataProvider &fdp) {
  int ci = fdp.ConsumeIntegralInRange<int>(0, kNumCodecDecoders - 1);
  std::string data = fdp.ConsumeRemainingBytesAsString();
  PyRef pydata = PyBytes_FromStringAndSize(Y(data));
  CHECK(pydata);
  PyRef r = PyObject_CallFunction(codecs_decode, "Oss",
                                  (PyObject *)pydata,
                                  kCodecDecoders[ci], "replace");
  if (PyErr_Occurred()) PyErr_Clear();
}

// OP_CODECS_ENCODE: Convert fuzz bytes to a Python str using a fuzz-chosen
// decoding (Latin-1, UTF-8, UTF-16-LE, or UTF-32-LE — see fuzz_bytes_to_str),
// then call codecs.encode(str, codec, 'replace') with a fuzz-chosen codec
// from 19 encoders. Exercises the multibytecodec_encode and built-in codec
// encode paths.
static void op_codecs_encode(FuzzedDataProvider &fdp) {
  int ci = fdp.ConsumeIntegralInRange<int>(0, kNumCodecEncoders - 1);
  int str_enc = fdp.ConsumeIntegralInRange<int>(0, 3);
  std::string data = fdp.ConsumeBytesAsString(
      std::min(fdp.remaining_bytes(), (size_t)10000));
  PyRef pystr(fuzz_bytes_to_str(data, str_enc));
  CHECK(pystr);
  PyRef r = PyObject_CallFunction(codecs_encode, "Oss",
                                  (PyObject *)pystr,
                                  kCodecEncoders[ci], "replace");
  if (PyErr_Occurred()) PyErr_Clear();
}

// OP_CODECS_INCREMENTAL_DECODE: Get an IncrementalDecoder for a fuzz-chosen
// codec from {shift_jis, gb18030, utf-16}, split the fuzz data at the
// midpoint, then: .decode(first_half), .decode(second_half, final=True),
// .getstate(), .reset(). Exercises the stateful incremental decoding path
// in _multibytecodec (MultibyteIncrementalDecoder_Type).
static void op_codecs_incremental_decode(FuzzedDataProvider &fdp) {
  static const char *kIncCodecs[] = {"shift_jis", "gb18030", "utf-16"};
  int ci = fdp.ConsumeIntegralInRange<int>(0, 2);
  std::string data = fdp.ConsumeRemainingBytesAsString();
  size_t mid = data.size() / 2;

  PyRef codec_name = PyUnicode_FromString(kIncCodecs[ci]);
  CHECK(codec_name);
  PyRef decoder_factory = PyObject_CallFunction(
      codecs_getincrementaldecoder, "O", (PyObject *)codec_name);
  CHECK(decoder_factory);

  PyRef decoder = PyObject_CallFunction(decoder_factory, "s", "replace");
  CHECK(decoder);

  PyRef half1 = PyBytes_FromStringAndSize(data.data(), mid);
  CHECK(half1);
  PyRef r1 = PyObject_CallMethod(decoder, "decode", "O",
                                 (PyObject *)half1);
  if (!r1) {
    PyErr_Clear();
    return;
  }

  PyRef half2 = PyBytes_FromStringAndSize(data.data() + mid,
                                          data.size() - mid);
  CHECK(half2);
  PyRef r2 = PyObject_CallMethod(decoder, "decode", "Oi",
                                 (PyObject *)half2, 1);
  if (PyErr_Occurred()) PyErr_Clear();

  PyRef state = PyObject_CallMethod(decoder, "getstate", NULL);
  if (PyErr_Occurred()) PyErr_Clear();
  PyRef reset = PyObject_CallMethod(decoder, "reset", NULL);
  if (PyErr_Occurred()) PyErr_Clear();
}

// OP_CODECS_INCREMENTAL_ENCODE: Get an IncrementalEncoder for a fuzz-chosen
// codec from {shift_jis, utf-8}. Convert fuzz bytes to str via fuzz-chosen
// decoding (see fuzz_bytes_to_str), split the resulting string at the
// midpoint, then: .encode(first_half), .reset(), .encode(second_half),
// .getstate(). Exercises the stateful incremental encoding path in
// _multibytecodec (MultibyteIncrementalEncoder_Type).
static void op_codecs_incremental_encode(FuzzedDataProvider &fdp) {
  static const char *kIncCodecs[] = {"shift_jis", "utf-8"};
  int ci = fdp.ConsumeIntegralInRange<int>(0, 1);
  int str_enc = fdp.ConsumeIntegralInRange<int>(0, 3);
  std::string data = fdp.ConsumeBytesAsString(
      std::min(fdp.remaining_bytes(), (size_t)10000));

  PyRef pystr(fuzz_bytes_to_str(data, str_enc));
  CHECK(pystr);
  Py_ssize_t slen = PyUnicode_GET_LENGTH(pystr);
  Py_ssize_t mid = slen / 2;

  PyRef codec_name = PyUnicode_FromString(kIncCodecs[ci]);
  CHECK(codec_name);
  PyRef encoder_factory = PyObject_CallFunction(
      codecs_getincrementalencoder, "O", (PyObject *)codec_name);
  CHECK(encoder_factory);

  PyRef encoder = PyObject_CallFunction(encoder_factory, "s", "replace");
  CHECK(encoder);

  PyRef half1 = PyUnicode_Substring(pystr, 0, mid);
  CHECK(half1);
  PyRef r1 = PyObject_CallMethod(encoder, "encode", "O",
                                 (PyObject *)half1);
  if (!r1) {
    PyErr_Clear();
    return;
  }

  PyRef reset_r = PyObject_CallMethod(encoder, "reset", NULL);
  if (PyErr_Occurred()) PyErr_Clear();

  PyRef half2 = PyUnicode_Substring(pystr, mid, slen);
  CHECK(half2);
  PyRef r2 = PyObject_CallMethod(encoder, "encode", "O",
                                 (PyObject *)half2);
  if (PyErr_Occurred()) PyErr_Clear();

  PyRef state = PyObject_CallMethod(encoder, "getstate", NULL);
  if (PyErr_Occurred()) PyErr_Clear();
}

// OP_CODECS_STREAM: Wrap fuzz data in BytesIO, create a UTF-8 StreamReader
// via codecs.getreader('utf-8')(bio, errors='replace'), then .read().
// Exercises the StreamReader code path (MultibyteStreamReader_Type for
// multibyte codecs, or built-in StreamReader for UTF-8).
static void op_codecs_stream(FuzzedDataProvider &fdp) {
  std::string data = fdp.ConsumeRemainingBytesAsString();
  PyRef pydata = PyBytes_FromStringAndSize(Y(data));
  CHECK(pydata);
  PyRef bio = PyObject_CallFunction(bytesio_ctor, "O",
                                    (PyObject *)pydata);
  CHECK(bio);

  PyRef reader_factory = PyObject_CallFunction(
      codecs_getreader, "s", "utf-8");
  CHECK(reader_factory);

  PyRef reader = PyObject_CallFunction(reader_factory, "Os",
                                       (PyObject *)bio, "replace");
  CHECK(reader);

  PyRef r = PyObject_CallMethod(reader, "read", NULL);
  if (PyErr_Occurred()) PyErr_Clear();
}

// ---------------------------------------------------------------------------
// Operations — SSL (1 op)
// ---------------------------------------------------------------------------

// OP_SSL_CERT: Call ssl.DER_cert_to_PEM_cert(data) to attempt DER-to-PEM
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

// ---------------------------------------------------------------------------
// Dispatch.
// ---------------------------------------------------------------------------

enum Op {
  OP_ZLIB_DECOMPRESS,
  OP_ZLIB_COMPRESS,
  OP_ZLIB_CHECKSUM,
  OP_BZ2,
  OP_LZMA_DECOMPRESS,
  OP_LZMA_COMPRESS,
  OP_BINASCII_DECODE,
  OP_BINASCII_ENCODE,
  OP_BINASCII_CHECKSUM,
  OP_BINASCII_ROUNDTRIP,
  OP_PICKLE_DUMPS,
  OP_PICKLE_LOADS,
  OP_PICKLE_PICKLER,
  OP_PICKLE_ROUNDTRIP,
  OP_CODECS_DECODE,
  OP_CODECS_ENCODE,
  OP_CODECS_INCREMENTAL_DECODE,
  OP_CODECS_INCREMENTAL_ENCODE,
  OP_CODECS_STREAM,
  OP_SSL_CERT,
  NUM_OPS
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  assert(Py_IsInitialized());
  init_decode();
  if (size < 1 || size > kMaxInputSize) return 0;
  if (PyErr_Occurred()) PyErr_Clear();

  FuzzedDataProvider fdp(data, size);
  switch (fdp.ConsumeIntegralInRange<int>(0, NUM_OPS - 1)) {
    case OP_ZLIB_DECOMPRESS:
      op_zlib_decompress(fdp);
      break;
    case OP_ZLIB_COMPRESS:
      op_zlib_compress(fdp);
      break;
    case OP_ZLIB_CHECKSUM:
      op_zlib_checksum(fdp);
      break;
    case OP_BZ2:
      op_bz2(fdp);
      break;
    case OP_LZMA_DECOMPRESS:
      op_lzma_decompress(fdp);
      break;
    case OP_LZMA_COMPRESS:
      op_lzma_compress(fdp);
      break;
    case OP_BINASCII_DECODE:
      op_binascii_decode(fdp);
      break;
    case OP_BINASCII_ENCODE:
      op_binascii_encode(fdp);
      break;
    case OP_BINASCII_CHECKSUM:
      op_binascii_checksum(fdp);
      break;
    case OP_BINASCII_ROUNDTRIP:
      op_binascii_roundtrip(fdp);
      break;
    case OP_PICKLE_DUMPS:
      op_pickle_dumps(fdp);
      break;
    case OP_PICKLE_LOADS:
      op_pickle_loads(fdp);
      break;
    case OP_PICKLE_PICKLER:
      op_pickle_pickler(fdp);
      break;
    case OP_PICKLE_ROUNDTRIP:
      op_pickle_roundtrip(fdp);
      break;
    case OP_CODECS_DECODE:
      op_codecs_decode(fdp);
      break;
    case OP_CODECS_ENCODE:
      op_codecs_encode(fdp);
      break;
    case OP_CODECS_INCREMENTAL_DECODE:
      op_codecs_incremental_decode(fdp);
      break;
    case OP_CODECS_INCREMENTAL_ENCODE:
      op_codecs_incremental_encode(fdp);
      break;
    case OP_CODECS_STREAM:
      op_codecs_stream(fdp);
      break;
    case OP_SSL_CERT:
      op_ssl_cert(fdp);
      break;
  }

  if (++gc_counter % kGcInterval == 0) PyGC_Collect();
  return 0;
}
