// fuzz_ioops.cpp — Fuzzer for CPython's I/O C extension modules.
//
// This fuzzer exercises the following CPython C extension modules via
// their Python API, called through the Python C API from C++:
//
//   _io/bytesio.c       — BytesIO: write, seek, read, readline, readlines,
//                          readinto, read1, readinto1, getvalue, getbuffer,
//                          truncate, tell, iteration, peek (via BufferedReader)
//   _io/textio.c        — TextIOWrapper: write, read, readline, readlines,
//                          flush, seek, reconfigure, detach, properties
//                          (readable/writable/seekable/encoding/buffer),
//                          IncrementalNewlineDecoder
//   _io/bufferedio.c    — BufferedReader, BufferedWriter, BufferedRandom,
//                          BufferedRWPair: read, write, peek, read1, readline,
//                          seek, tell, truncate, flush, detach, raw
//   _io/fileio.c        — FileIO: read, readall, readinto, write, flush,
//                          tell, seek, truncate, fileno, isatty, name, mode,
//                          closefd, readable, writable, seekable
//   _io/_iomodule.c     — io.open() with various modes (r, rb, w, wb)
//   _io/stringio.c      — StringIO: write, seek, readline, readlines,
//                          truncate, tell, close
//
// The first byte of fuzz input selects one of 7 operation types. Each
// operation consumes further bytes via FuzzedDataProvider to parameterize
// the call (encoding, error handler, newline mode, I/O variant).
//
// All module functions and class constructors are imported once during init
// and cached as static PyObject* pointers. Temporary directory and test file
// are created once at init. PyRef (RAII) prevents reference leaks.
// PyGC_Collect() runs every 200 iterations. Max input size: 64 KB.

#include "fuzz_helpers.h"

// ---------------------------------------------------------------------------
// Cached module objects, initialized once.
// ---------------------------------------------------------------------------

// io classes
static PyObject *io_BytesIO, *io_TextIOWrapper;
static PyObject *io_BufferedReader, *io_BufferedWriter;
static PyObject *io_BufferedRandom, *io_BufferedRWPair;
static PyObject *io_FileIO, *io_open, *io_StringIO;
static PyObject *io_IncrementalNewlineDecoder;

// os
static PyObject *os_path_join, *os_open_fn, *os_unlink;
static PyObject *os_O_RDONLY;

// Temp paths (as C strings).
static char tmpdir[256];
static char tmpfile_path[256];

static unsigned long gc_counter = 0;

static int initialized = 0;

static void init_ioops(void) {
  if (initialized) return;

  // io
  io_BytesIO = import_attr("io", "BytesIO");
  io_TextIOWrapper = import_attr("io", "TextIOWrapper");
  io_BufferedReader = import_attr("io", "BufferedReader");
  io_BufferedWriter = import_attr("io", "BufferedWriter");
  io_BufferedRandom = import_attr("io", "BufferedRandom");
  io_BufferedRWPair = import_attr("io", "BufferedRWPair");
  io_FileIO = import_attr("io", "FileIO");
  io_open = import_attr("io", "open");
  io_StringIO = import_attr("io", "StringIO");
  io_IncrementalNewlineDecoder = import_attr("io",
                                             "IncrementalNewlineDecoder");

  // os
  os_path_join = import_attr("os.path", "join");
  os_open_fn = import_attr("os", "open");
  os_unlink = import_attr("os", "unlink");
  os_O_RDONLY = import_attr("os", "O_RDONLY");

  // Create temp directory and test file.
  {
    PyObject *globals = PyDict_New();
    PyDict_SetItemString(globals, "__builtins__", PyEval_GetBuiltins());
    PyObject *r = PyRun_String(
        "import tempfile, os\n"
        "_tmpdir = tempfile.mkdtemp(prefix='fuzz_io_')\n"
        "_tmpfile = os.path.join(_tmpdir, 'test')\n"
        "with open(_tmpfile, 'wb') as f:\n"
        "    f.write(b'A' * 4096)\n",
        Py_file_input, globals, globals);
    if (!r) { PyErr_Print(); abort(); }
    Py_DECREF(r);
    PyObject *td = PyDict_GetItemString(globals, "_tmpdir");
    PyObject *tf = PyDict_GetItemString(globals, "_tmpfile");
    const char *td_str = PyUnicode_AsUTF8(td);
    const char *tf_str = PyUnicode_AsUTF8(tf);
    snprintf(tmpdir, sizeof(tmpdir), "%s", td_str);
    snprintf(tmpfile_path, sizeof(tmpfile_path), "%s", tf_str);
    Py_DECREF(globals);
  }

  // Suppress warnings.
  PyRun_SimpleString("import warnings; warnings.filterwarnings('ignore')");

  assert(!PyErr_Occurred());
  initialized = 1;
}

// Helper: Build a temp file path.
static PyObject *make_tmppath(const char *name) {
  return PyObject_CallFunction(os_path_join, "ss", tmpdir, name);
}

// Helper: Unlink a file (ignore errors).
static void unlink_path(PyObject *path) {
  PyRef r = PyObject_CallFunction(os_unlink, "O", path);
  if (PyErr_Occurred()) PyErr_Clear();
}

// ---------------------------------------------------------------------------
// Operations (7 ops).
// ---------------------------------------------------------------------------

// OP_BYTESIO: BytesIO with fuzz data, then FDP selects actions.
// Exercises _io/bytesio.c paths.
static void op_bytesio(FuzzedDataProvider &fdp) {
  int variant = fdp.ConsumeIntegralInRange<int>(0, 6);
  std::string data = fdp.ConsumeBytesAsString(
      std::min(fdp.remaining_bytes(), (size_t)10000));
  PyRef pydata = PyBytes_FromStringAndSize(Y(data));
  CHECK(pydata);

  switch (variant) {
    case 0: {
      // Basic: write/seek/read/getvalue/tell.
      PyRef bio = PyObject_CallFunction(io_BytesIO, NULL);
      CHECK(bio);
      PyRef wr = PyObject_CallMethod(bio, "write", "O", (PyObject *)pydata);
      if (!wr) { PyErr_Clear(); break; }
      PyRef sk = PyObject_CallMethod(bio, "seek", "i", 0);
      if (PyErr_Occurred()) PyErr_Clear();
      PyRef rd = PyObject_CallMethod(bio, "read", NULL);
      if (PyErr_Occurred()) PyErr_Clear();
      PyRef gv = PyObject_CallMethod(bio, "getvalue", NULL);
      if (PyErr_Occurred()) PyErr_Clear();
      PyRef tl = PyObject_CallMethod(bio, "tell", NULL);
      if (PyErr_Occurred()) PyErr_Clear();
      PyRef cl = PyObject_CallMethod(bio, "close", NULL);
      if (PyErr_Occurred()) PyErr_Clear();
      break;
    }
    case 1: {
      // readline, readlines, readinto.
      PyRef bio = PyObject_CallFunction(io_BytesIO, "O", (PyObject *)pydata);
      CHECK(bio);
      {
        PyRef r = PyObject_CallMethod(bio, "readline", NULL);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        PyRef sk = PyObject_CallMethod(bio, "seek", "i", 0);
        if (PyErr_Occurred()) PyErr_Clear();
        PyRef r = PyObject_CallMethod(bio, "readlines", NULL);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        PyRef sk = PyObject_CallMethod(bio, "seek", "i", 0);
        if (PyErr_Occurred()) PyErr_Clear();
        PyRef buf = PyByteArray_FromStringAndSize(NULL, 32);
        CHECK(buf);
        PyRef r = PyObject_CallMethod(bio, "readinto", "O", (PyObject *)buf);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      PyRef cl = PyObject_CallMethod(bio, "close", NULL);
      if (PyErr_Occurred()) PyErr_Clear();
      break;
    }
    case 2: {
      // truncate + write + getvalue.
      PyRef bio = PyObject_CallFunction(io_BytesIO, "O", (PyObject *)pydata);
      CHECK(bio);
      long trunc_at = data.size() < 64 ? data.size() : 64;
      PyRef tr = PyObject_CallMethod(bio, "truncate", "l", trunc_at);
      if (PyErr_Occurred()) PyErr_Clear();
      PyRef wr = PyObject_CallMethod(bio, "write", "y#", "XX", 2);
      if (PyErr_Occurred()) PyErr_Clear();
      PyRef gv = PyObject_CallMethod(bio, "getvalue", NULL);
      if (PyErr_Occurred()) PyErr_Clear();
      PyRef cl = PyObject_CallMethod(bio, "close", NULL);
      if (PyErr_Occurred()) PyErr_Clear();
      break;
    }
    case 3: {
      // getbuffer (memoryview).
      PyRef bio = PyObject_CallFunction(io_BytesIO, "O", (PyObject *)pydata);
      CHECK(bio);
      PyRef mv = PyObject_CallMethod(bio, "getbuffer", NULL);
      if (mv) {
        PyRef bytes_val = PyObject_CallFunction(
            (PyObject *)&PyBytes_Type, "O", (PyObject *)mv);
        if (PyErr_Occurred()) PyErr_Clear();
        PyRef rel = PyObject_CallMethod(mv, "release", NULL);
        if (PyErr_Occurred()) PyErr_Clear();
      } else {
        PyErr_Clear();
      }
      PyRef cl = PyObject_CallMethod(bio, "close", NULL);
      if (PyErr_Occurred()) PyErr_Clear();
      break;
    }
    case 4: {
      // read1, readinto1.
      PyRef bio = PyObject_CallFunction(io_BytesIO, "O", (PyObject *)pydata);
      CHECK(bio);
      {
        PyRef r = PyObject_CallMethod(bio, "read1", "i", 16);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        PyRef sk = PyObject_CallMethod(bio, "seek", "i", 0);
        if (PyErr_Occurred()) PyErr_Clear();
        PyRef buf = PyByteArray_FromStringAndSize(NULL, 32);
        CHECK(buf);
        PyRef r = PyObject_CallMethod(bio, "readinto1", "O", (PyObject *)buf);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      PyRef cl = PyObject_CallMethod(bio, "close", NULL);
      if (PyErr_Occurred()) PyErr_Clear();
      break;
    }
    case 5: {
      // Iteration.
      PyRef bio = PyObject_CallFunction(io_BytesIO, "O", (PyObject *)pydata);
      CHECK(bio);
      PyRef it = PyObject_GetIter(bio);
      if (it) {
        PyObject *line;
        while ((line = PyIter_Next(it)) != NULL)
          Py_DECREF(line);
        if (PyErr_Occurred()) PyErr_Clear();
      } else {
        PyErr_Clear();
      }
      PyRef cl = PyObject_CallMethod(bio, "close", NULL);
      if (PyErr_Occurred()) PyErr_Clear();
      break;
    }
    case 6: {
      // Peek via BufferedReader wrapping.
      PyRef bio = PyObject_CallFunction(io_BytesIO, "O", (PyObject *)pydata);
      CHECK(bio);
      PyRef br = PyObject_CallFunction(io_BufferedReader, "O",
                                       (PyObject *)bio);
      CHECK(br);
      {
        PyRef r = PyObject_CallMethod(br, "peek", "i", 16);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        PyRef r = PyObject_CallMethod(br, "read", "i", 8);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        PyRef r = PyObject_CallMethod(br, "read1", "i", 8);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      PyRef cl = PyObject_CallMethod(br, "close", NULL);
      if (PyErr_Occurred()) PyErr_Clear();
      break;
    }
  }
}

// OP_TEXTIOWRAPPER: FDP selects encoding, errors, newline. Create BytesIO +
// TextIOWrapper. Exercises _io/textio.c paths.
static void op_textiowrapper(FuzzedDataProvider &fdp) {
  static const char *kEncodings[] = {"utf-8", "latin-1", "ascii", "utf-16"};
  static const char *kErrors[] = {
    "strict", "replace", "xmlcharrefreplace", "backslashreplace",
  };
  // NULL = universal newline mode.
  static const char *kNewlines[] = {NULL, "\n", "\r\n", ""};

  int enc_idx = fdp.ConsumeIntegralInRange<int>(0, 3);
  int err_idx = fdp.ConsumeIntegralInRange<int>(0, 3);
  int nl_idx = fdp.ConsumeIntegralInRange<int>(0, 3);
  int variant = fdp.ConsumeIntegralInRange<int>(0, 4);
  int str_enc = fdp.ConsumeIntegralInRange<int>(0, 3);
  std::string data = fdp.ConsumeBytesAsString(
      std::min(fdp.remaining_bytes(), (size_t)10000));

  const char *encoding = kEncodings[enc_idx];
  const char *errors = kErrors[err_idx];
  const char *newline = kNewlines[nl_idx];

  switch (variant) {
    case 0: {
      // Write mode: write string, flush, seek, read.
      PyRef bio = PyObject_CallFunction(io_BytesIO, NULL);
      CHECK(bio);
      PyRef kwargs = PyDict_New();
      CHECK(kwargs);
      PyRef enc_str = PyUnicode_FromString(encoding);
      CHECK(enc_str);
      PyDict_SetItemString(kwargs, "encoding", enc_str);
      PyRef err_str = PyUnicode_FromString(errors);
      CHECK(err_str);
      PyDict_SetItemString(kwargs, "errors", err_str);
      if (newline) {
        PyRef nl_str = PyUnicode_FromString(newline);
        CHECK(nl_str);
        PyDict_SetItemString(kwargs, "newline", nl_str);
      }
      PyRef args = PyTuple_Pack(1, (PyObject *)bio);
      CHECK(args);
      PyRef tw = PyObject_Call(io_TextIOWrapper, args, kwargs);
      CHECK(tw);

      PyRef pystr(fuzz_bytes_to_str(data, str_enc));
      CHECK(pystr);
      {
        PyRef r = PyObject_CallMethod(tw, "write", "O", (PyObject *)pystr);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        PyRef r = PyObject_CallMethod(tw, "flush", NULL);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        PyRef r = PyObject_CallMethod(tw, "seek", "i", 0);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        PyRef r = PyObject_CallMethod(tw, "read", NULL);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        PyRef r = PyObject_CallMethod(tw, "close", NULL);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      break;
    }
    case 1: {
      // Read mode: BytesIO(data) + TextIOWrapper, read/readline/readlines.
      PyRef pydata = PyBytes_FromStringAndSize(Y(data));
      CHECK(pydata);
      PyRef bio = PyObject_CallFunction(io_BytesIO, "O", (PyObject *)pydata);
      CHECK(bio);
      PyRef kwargs = PyDict_New();
      CHECK(kwargs);
      PyRef enc_str = PyUnicode_FromString(encoding);
      CHECK(enc_str);
      PyDict_SetItemString(kwargs, "encoding", enc_str);
      PyRef err_str = PyUnicode_FromString("replace");
      CHECK(err_str);
      PyDict_SetItemString(kwargs, "errors", err_str);
      PyRef args = PyTuple_Pack(1, (PyObject *)bio);
      CHECK(args);
      PyRef tw = PyObject_Call(io_TextIOWrapper, args, kwargs);
      CHECK(tw);

      // readline x3.
      for (int i = 0; i < 3; i++) {
        PyRef r = PyObject_CallMethod(tw, "readline", NULL);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        PyRef sk = PyObject_CallMethod(tw, "seek", "i", 0);
        if (PyErr_Occurred()) PyErr_Clear();
        PyRef r = PyObject_CallMethod(tw, "readlines", NULL);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        PyRef sk = PyObject_CallMethod(tw, "seek", "i", 0);
        if (PyErr_Occurred()) PyErr_Clear();
        PyRef r = PyObject_CallMethod(tw, "read", "i", 16);
        if (PyErr_Occurred()) PyErr_Clear();
        PyRef r2 = PyObject_CallMethod(tw, "read", "i", 16);
        if (PyErr_Occurred()) PyErr_Clear();
        PyRef r3 = PyObject_CallMethod(tw, "read", NULL);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        PyRef r = PyObject_CallMethod(tw, "close", NULL);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      break;
    }
    case 2: {
      // Reconfigure: write, reconfigure, write more, read.
      PyRef bio = PyObject_CallFunction(io_BytesIO, NULL);
      CHECK(bio);
      PyRef kwargs = PyDict_New();
      CHECK(kwargs);
      PyRef enc_str = PyUnicode_FromString("utf-8");
      CHECK(enc_str);
      PyDict_SetItemString(kwargs, "encoding", enc_str);
      PyRef args = PyTuple_Pack(1, (PyObject *)bio);
      CHECK(args);
      PyRef tw = PyObject_Call(io_TextIOWrapper, args, kwargs);
      CHECK(tw);

      PyRef pystr(fuzz_bytes_to_str(data, str_enc));
      CHECK(pystr);
      {
        PyRef r = PyObject_CallMethod(tw, "write", "O", (PyObject *)pystr);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        PyRef kw = PyDict_New();
        CHECK(kw);
        PyRef nl = PyUnicode_FromString("\n");
        CHECK(nl);
        PyDict_SetItemString(kw, "newline", nl);
        PyDict_SetItemString(kw, "line_buffering", Py_True);
        PyRef empty = PyTuple_New(0);
        CHECK(empty);
        PyRef r = PyObject_Call(
            PyObject_GetAttrString(tw, "reconfigure"), empty, kw);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        PyRef sub = PyUnicode_Substring(pystr, 0, 32);
        if (sub) {
          PyRef r = PyObject_CallMethod(tw, "write", "O", (PyObject *)sub);
          if (PyErr_Occurred()) PyErr_Clear();
        } else {
          PyErr_Clear();
        }
      }
      {
        PyRef r = PyObject_CallMethod(tw, "seek", "i", 0);
        if (PyErr_Occurred()) PyErr_Clear();
        PyRef rd = PyObject_CallMethod(tw, "read", NULL);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        PyRef r = PyObject_CallMethod(tw, "close", NULL);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      break;
    }
    case 3: {
      // Detach.
      PyRef pydata = PyBytes_FromStringAndSize(Y(data));
      CHECK(pydata);
      PyRef bio = PyObject_CallFunction(io_BytesIO, "O", (PyObject *)pydata);
      CHECK(bio);
      PyRef kwargs = PyDict_New();
      CHECK(kwargs);
      PyRef enc_str = PyUnicode_FromString("utf-8");
      CHECK(enc_str);
      PyDict_SetItemString(kwargs, "encoding", enc_str);
      PyRef err_str = PyUnicode_FromString("replace");
      CHECK(err_str);
      PyDict_SetItemString(kwargs, "errors", err_str);
      PyRef args = PyTuple_Pack(1, (PyObject *)bio);
      CHECK(args);
      PyRef tw = PyObject_Call(io_TextIOWrapper, args, kwargs);
      CHECK(tw);
      {
        PyRef r = PyObject_CallMethod(tw, "read", "i", 4);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        PyRef raw = PyObject_CallMethod(tw, "detach", NULL);
        if (raw) {
          PyRef rd = PyObject_CallMethod(raw, "read", NULL);
          if (PyErr_Occurred()) PyErr_Clear();
          PyRef cl = PyObject_CallMethod(raw, "close", NULL);
          if (PyErr_Occurred()) PyErr_Clear();
        } else {
          PyErr_Clear();
        }
      }
      break;
    }
    case 4: {
      // Properties: writable/readable/seekable/encoding/buffer.
      PyRef pydata = PyBytes_FromStringAndSize(Y(data));
      CHECK(pydata);
      PyRef bio = PyObject_CallFunction(io_BytesIO, "O", (PyObject *)pydata);
      CHECK(bio);
      PyRef kwargs = PyDict_New();
      CHECK(kwargs);
      PyRef enc_str = PyUnicode_FromString("utf-8");
      CHECK(enc_str);
      PyDict_SetItemString(kwargs, "encoding", enc_str);
      PyRef err_str = PyUnicode_FromString("replace");
      CHECK(err_str);
      PyDict_SetItemString(kwargs, "errors", err_str);
      PyRef args = PyTuple_Pack(1, (PyObject *)bio);
      CHECK(args);
      PyRef tw = PyObject_Call(io_TextIOWrapper, args, kwargs);
      CHECK(tw);
      {
        PyRef r = PyObject_CallMethod(tw, "writable", NULL);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        PyRef r = PyObject_CallMethod(tw, "readable", NULL);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        PyRef r = PyObject_CallMethod(tw, "seekable", NULL);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        PyRef r = PyObject_GetAttrString(tw, "encoding");
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        PyRef r = PyObject_GetAttrString(tw, "buffer");
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        PyRef r = PyObject_CallMethod(tw, "close", NULL);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      break;
    }
  }
}

// OP_BUFFERED_IO: FDP selects variant — BufferedReader, BufferedWriter,
// BufferedRandom, BufferedRWPair. Exercises _io/bufferedio.c paths.
static void op_buffered_io(FuzzedDataProvider &fdp) {
  int variant = fdp.ConsumeIntegralInRange<int>(0, 3);
  std::string data = fdp.ConsumeBytesAsString(
      std::min(fdp.remaining_bytes(), (size_t)10000));
  PyRef pydata = PyBytes_FromStringAndSize(Y(data));
  CHECK(pydata);

  switch (variant) {
    case 0: {
      // BufferedReader wrapping BytesIO.
      PyRef bio = PyObject_CallFunction(io_BytesIO, "O", (PyObject *)pydata);
      CHECK(bio);
      PyRef br = PyObject_CallFunction(io_BufferedReader, "O",
                                       (PyObject *)bio);
      CHECK(br);
      {
        PyRef r = PyObject_CallMethod(br, "read", "i", 64);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        PyRef r = PyObject_CallMethod(br, "seek", "i", 0);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        PyRef r = PyObject_CallMethod(br, "peek", "i", 16);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        PyRef r = PyObject_CallMethod(br, "read1", "i", 16);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        PyRef r = PyObject_CallMethod(br, "readline", NULL);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        PyRef raw = PyObject_GetAttrString(br, "raw");
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        PyRef det = PyObject_CallMethod(br, "detach", NULL);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      break;
    }
    case 1: {
      // BufferedWriter wrapping BytesIO.
      PyRef bio = PyObject_CallFunction(io_BytesIO, NULL);
      CHECK(bio);
      PyRef bw = PyObject_CallFunction(io_BufferedWriter, "O",
                                       (PyObject *)bio);
      CHECK(bw);
      {
        PyRef r = PyObject_CallMethod(bw, "write", "O", (PyObject *)pydata);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        PyRef r = PyObject_CallMethod(bw, "flush", NULL);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        PyRef r = PyObject_CallMethod(bw, "close", NULL);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      break;
    }
    case 2: {
      // BufferedRandom wrapping BytesIO.
      PyRef bio = PyObject_CallFunction(io_BytesIO, "O", (PyObject *)pydata);
      CHECK(bio);
      PyRef brnd = PyObject_CallFunction(io_BufferedRandom, "O",
                                         (PyObject *)bio);
      CHECK(brnd);
      {
        PyRef r = PyObject_CallMethod(brnd, "write", "O", (PyObject *)pydata);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        PyRef r = PyObject_CallMethod(brnd, "seek", "i", 0);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        PyRef r = PyObject_CallMethod(brnd, "read", "i", 64);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        PyRef r = PyObject_CallMethod(brnd, "tell", NULL);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        long trunc_at = data.size() < 64 ? data.size() : 64;
        PyRef r = PyObject_CallMethod(brnd, "truncate", "l", trunc_at);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        PyRef r = PyObject_CallMethod(brnd, "close", NULL);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      break;
    }
    case 3: {
      // BufferedRWPair.
      PyRef r_bio = PyObject_CallFunction(io_BytesIO, "O",
                                          (PyObject *)pydata);
      CHECK(r_bio);
      PyRef w_bio = PyObject_CallFunction(io_BytesIO, NULL);
      CHECK(w_bio);
      PyRef rw = PyObject_CallFunction(io_BufferedRWPair, "OO",
                                       (PyObject *)r_bio, (PyObject *)w_bio);
      CHECK(rw);
      {
        PyRef r = PyObject_CallMethod(rw, "read", "i", 32);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        PyRef r = PyObject_CallMethod(rw, "write", "O", (PyObject *)pydata);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        PyRef r = PyObject_CallMethod(rw, "close", NULL);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      break;
    }
  }
}

// OP_FILEIO: FDP selects mode — read, write, read+write.
// Exercises _io/fileio.c paths.
static void op_fileio(FuzzedDataProvider &fdp) {
  int variant = fdp.ConsumeIntegralInRange<int>(0, 2);
  std::string data = fdp.ConsumeBytesAsString(
      std::min(fdp.remaining_bytes(), (size_t)10000));

  switch (variant) {
    case 0: {
      // Read from tmpfile.
      PyRef fio = PyObject_CallFunction(io_FileIO, "ss",
                                        tmpfile_path, "r");
      CHECK(fio);
      {
        PyRef r = PyObject_CallMethod(fio, "read", "i", 64);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        PyRef r = PyObject_CallMethod(fio, "seek", "i", 0);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        PyRef r = PyObject_CallMethod(fio, "readall", NULL);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        PyRef sk = PyObject_CallMethod(fio, "seek", "i", 0);
        if (PyErr_Occurred()) PyErr_Clear();
        PyRef buf = PyByteArray_FromStringAndSize(NULL, 64);
        CHECK(buf);
        PyRef r = PyObject_CallMethod(fio, "readinto", "O", (PyObject *)buf);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        PyRef r = PyObject_CallMethod(fio, "fileno", NULL);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        PyRef r = PyObject_CallMethod(fio, "isatty", NULL);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        PyRef r = PyObject_GetAttrString(fio, "name");
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        PyRef r = PyObject_GetAttrString(fio, "mode");
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        PyRef r = PyObject_CallMethod(fio, "readable", NULL);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        PyRef r = PyObject_CallMethod(fio, "seekable", NULL);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        PyRef r = PyObject_CallMethod(fio, "close", NULL);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      break;
    }
    case 1: {
      // Write to temp file.
      PyRef path(make_tmppath("fio_w"));
      CHECK(path);
      PyRef fio = PyObject_CallFunction(io_FileIO, "Os",
                                        (PyObject *)path, "w");
      CHECK(fio);
      {
        PyRef pydata = PyBytes_FromStringAndSize(Y(data));
        CHECK(pydata);
        PyRef r = PyObject_CallMethod(fio, "write", "O", (PyObject *)pydata);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        PyRef r = PyObject_CallMethod(fio, "flush", NULL);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        PyRef r = PyObject_CallMethod(fio, "tell", NULL);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        PyRef r = PyObject_CallMethod(fio, "close", NULL);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      unlink_path(path);
      break;
    }
    case 2: {
      // Read+write mode.
      PyRef path(make_tmppath("fio_rw"));
      CHECK(path);
      PyRef fio = PyObject_CallFunction(io_FileIO, "Os",
                                        (PyObject *)path, "w+b");
      CHECK(fio);
      {
        PyRef pydata = PyBytes_FromStringAndSize(Y(data));
        CHECK(pydata);
        PyRef r = PyObject_CallMethod(fio, "write", "O", (PyObject *)pydata);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        PyRef r = PyObject_CallMethod(fio, "seek", "i", 0);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        PyRef r = PyObject_CallMethod(fio, "read", "i", 32);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        PyRef r = PyObject_CallMethod(fio, "truncate", "i", 128);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        PyRef r = PyObject_CallMethod(fio, "close", NULL);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      unlink_path(path);
      break;
    }
  }
}

// OP_IO_OPEN: FDP selects mode — read text, read binary, write text, write binary.
// Exercises _io/_iomodule.c open() paths.
static void op_io_open(FuzzedDataProvider &fdp) {
  int variant = fdp.ConsumeIntegralInRange<int>(0, 3);
  int str_enc = fdp.ConsumeIntegralInRange<int>(0, 3);
  std::string data = fdp.ConsumeBytesAsString(
      std::min(fdp.remaining_bytes(), (size_t)10000));

  switch (variant) {
    case 0: {
      // Read text from tmpfile.
      PyRef f = PyObject_CallFunction(io_open, "ss", tmpfile_path, "r");
      CHECK(f);
      PyRef r = PyObject_CallMethod(f, "read", NULL);
      if (PyErr_Occurred()) PyErr_Clear();
      PyRef cl = PyObject_CallMethod(f, "close", NULL);
      if (PyErr_Occurred()) PyErr_Clear();
      break;
    }
    case 1: {
      // Read binary from tmpfile.
      PyRef f = PyObject_CallFunction(io_open, "ss", tmpfile_path, "rb");
      CHECK(f);
      PyRef r = PyObject_CallMethod(f, "read", NULL);
      if (PyErr_Occurred()) PyErr_Clear();
      PyRef cl = PyObject_CallMethod(f, "close", NULL);
      if (PyErr_Occurred()) PyErr_Clear();
      break;
    }
    case 2: {
      // Write text.
      PyRef path(make_tmppath("ioopen_w"));
      CHECK(path);
      PyRef pystr(fuzz_bytes_to_str(data, str_enc));
      CHECK(pystr);
      PyRef f = PyObject_CallFunction(io_open, "Os", (PyObject *)path, "w");
      CHECK(f);
      PyRef r = PyObject_CallMethod(f, "write", "O", (PyObject *)pystr);
      if (PyErr_Occurred()) PyErr_Clear();
      PyRef cl = PyObject_CallMethod(f, "close", NULL);
      if (PyErr_Occurred()) PyErr_Clear();
      unlink_path(path);
      break;
    }
    case 3: {
      // Write binary then read back.
      PyRef path(make_tmppath("ioopen_wb"));
      CHECK(path);
      PyRef pydata = PyBytes_FromStringAndSize(Y(data));
      CHECK(pydata);
      {
        PyRef f = PyObject_CallFunction(io_open, "Os",
                                        (PyObject *)path, "wb");
        CHECK(f);
        PyRef r = PyObject_CallMethod(f, "write", "O", (PyObject *)pydata);
        if (PyErr_Occurred()) PyErr_Clear();
        PyRef cl = PyObject_CallMethod(f, "close", NULL);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      // Read back.
      {
        PyRef kwargs = PyDict_New();
        CHECK(kwargs);
        PyRef err = PyUnicode_FromString("replace");
        CHECK(err);
        PyDict_SetItemString(kwargs, "errors", err);
        PyRef args = PyTuple_Pack(1, (PyObject *)path);
        CHECK(args);
        PyRef f = PyObject_Call(io_open, args, kwargs);
        if (f) {
          PyRef r = PyObject_CallMethod(f, "read", NULL);
          if (PyErr_Occurred()) PyErr_Clear();
          PyRef cl = PyObject_CallMethod(f, "close", NULL);
          if (PyErr_Occurred()) PyErr_Clear();
        } else {
          PyErr_Clear();
        }
      }
      unlink_path(path);
      break;
    }
  }
}

// OP_NEWLINE_DECODER: FDP selects translate mode. Create
// IncrementalNewlineDecoder, split str at midpoint, decode halves.
// Exercises _io/textio.c's newline decoder paths.
static void op_newline_decoder(FuzzedDataProvider &fdp) {
  bool translate = fdp.ConsumeBool();
  int str_enc = fdp.ConsumeIntegralInRange<int>(0, 3);
  std::string data = fdp.ConsumeBytesAsString(
      std::min(fdp.remaining_bytes(), (size_t)10000));
  PyRef pystr(fuzz_bytes_to_str(data, str_enc));
  CHECK(pystr);

  PyRef dec = PyObject_CallFunction(io_IncrementalNewlineDecoder, "OO",
                                    Py_None,
                                    translate ? Py_True : Py_False);
  CHECK(dec);

  Py_ssize_t slen = PyUnicode_GET_LENGTH(pystr);
  Py_ssize_t mid = slen / 2;

  PyRef half1 = PyUnicode_Substring(pystr, 0, mid);
  CHECK(half1);
  PyRef half2 = PyUnicode_Substring(pystr, mid, slen);
  CHECK(half2);

  {
    PyRef r = PyObject_CallMethod(dec, "decode", "O", (PyObject *)half1);
    if (PyErr_Occurred()) PyErr_Clear();
  }
  {
    PyRef r = PyObject_CallMethod(dec, "decode", "Oi",
                                  (PyObject *)half2, 1);
    if (PyErr_Occurred()) PyErr_Clear();
  }
  {
    PyRef state = PyObject_CallMethod(dec, "getstate", NULL);
    if (PyErr_Occurred()) PyErr_Clear();

    PyRef reset = PyObject_CallMethod(dec, "reset", NULL);
    if (PyErr_Occurred()) PyErr_Clear();

    if (state && state.p != Py_None) {
      PyRef ss = PyObject_CallMethod(dec, "setstate", "O",
                                     (PyObject *)state);
      if (PyErr_Occurred()) PyErr_Clear();
    }
  }
}

// OP_STRINGIO: StringIO write/readline/readlines/truncate/close.
// Exercises _io/stringio.c paths.
static void op_stringio(FuzzedDataProvider &fdp) {
  int str_enc = fdp.ConsumeIntegralInRange<int>(0, 3);
  int variant = fdp.ConsumeIntegralInRange<int>(0, 1);
  std::string data = fdp.ConsumeBytesAsString(
      std::min(fdp.remaining_bytes(), (size_t)10000));
  PyRef pystr(fuzz_bytes_to_str(data, str_enc));
  CHECK(pystr);

  PyRef sio = PyObject_CallFunction(io_StringIO, NULL);
  CHECK(sio);

  {
    PyRef r = PyObject_CallMethod(sio, "write", "O", (PyObject *)pystr);
    if (!r) { PyErr_Clear(); return; }
  }
  {
    PyRef r = PyObject_CallMethod(sio, "seek", "i", 0);
    if (PyErr_Occurred()) PyErr_Clear();
  }

  if (variant == 0) {
    // readline x3 + readlines.
    for (int i = 0; i < 3; i++) {
      PyRef r = PyObject_CallMethod(sio, "readline", NULL);
      if (PyErr_Occurred()) PyErr_Clear();
    }
    {
      PyRef sk = PyObject_CallMethod(sio, "seek", "i", 0);
      if (PyErr_Occurred()) PyErr_Clear();
      PyRef r = PyObject_CallMethod(sio, "readlines", NULL);
      if (PyErr_Occurred()) PyErr_Clear();
    }
  } else {
    // readlines on initial content.
    PyRef r = PyObject_CallMethod(sio, "readlines", NULL);
    if (PyErr_Occurred()) PyErr_Clear();
  }

  {
    Py_ssize_t slen = PyUnicode_GET_LENGTH(pystr);
    long trunc_at = slen < 64 ? slen : 64;
    PyRef r = PyObject_CallMethod(sio, "truncate", "l", trunc_at);
    if (PyErr_Occurred()) PyErr_Clear();
  }
  {
    PyRef r = PyObject_CallMethod(sio, "tell", NULL);
    if (PyErr_Occurred()) PyErr_Clear();
  }
  {
    PyRef r = PyObject_CallMethod(sio, "close", NULL);
    if (PyErr_Occurred()) PyErr_Clear();
  }
}

// ---------------------------------------------------------------------------
// Dispatch.
// ---------------------------------------------------------------------------

enum Op {
  OP_BYTESIO,
  OP_TEXTIOWRAPPER,
  OP_BUFFERED_IO,
  OP_FILEIO,
  OP_IO_OPEN,
  OP_NEWLINE_DECODER,
  OP_STRINGIO,
  NUM_OPS
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  assert(Py_IsInitialized());
  init_ioops();
  if (size < 1 || size > 0x10000) return 0;
  if (PyErr_Occurred()) PyErr_Clear();

  FuzzedDataProvider fdp(data, size);
  switch (fdp.ConsumeIntegralInRange<int>(0, NUM_OPS - 1)) {
    case OP_BYTESIO:
      op_bytesio(fdp);
      break;
    case OP_TEXTIOWRAPPER:
      op_textiowrapper(fdp);
      break;
    case OP_BUFFERED_IO:
      op_buffered_io(fdp);
      break;
    case OP_FILEIO:
      op_fileio(fdp);
      break;
    case OP_IO_OPEN:
      op_io_open(fdp);
      break;
    case OP_NEWLINE_DECODER:
      op_newline_decoder(fdp);
      break;
    case OP_STRINGIO:
      op_stringio(fdp);
      break;
  }

  if (++gc_counter % kGcInterval == 0) PyGC_Collect();
  return 0;
}
