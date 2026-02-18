// fuzz_parsers.cpp — Fuzzer for CPython's parser and text processing C
// extension modules.
//
// This fuzzer exercises the following CPython C extension modules via
// their Python API, called through the Python C API from C++:
//
//   _json               — json.dumps(), JSONEncoder with various options
//   _csv                — csv.Sniffer.sniff/has_header, csv.writer,
//                          csv.DictWriter with quoting modes
//   pyexpat             — ParserCreate with encodings/namespace_separator,
//                          Parse, ParseFile, handlers, GetInputContext
//   time                — strftime with fuzz format, strptime with fuzz input
//   _operator           — lt, gt, eq, ne, contains, countOf, indexOf,
//                          length_hint, concat, getitem, methodcaller
//   _locale             — strxfrm, strcoll, getlocale
//   _opcode (via dis)   — dis.dis() on compiled code
//
// The first byte of fuzz input selects one of 7 operation types. Each
// operation consumes further bytes via FuzzedDataProvider to parameterize
// the call (encoder options, parser encoding, operator selection).
//
// All module functions and class constructors are imported once during init
// and cached as static PyObject* pointers. PyRef (RAII) prevents reference
// leaks. PyGC_Collect() runs every 200 iterations. Max input size: 64 KB.

#include "fuzz_helpers.h"

// ---------------------------------------------------------------------------
// Cached module objects, initialized once.
// ---------------------------------------------------------------------------

// json
static PyObject *json_dumps, *json_JSONEncoder;

// csv
static PyObject *csv_Sniffer, *csv_writer, *csv_DictWriter;
static PyObject *csv_QUOTE_ALL, *csv_QUOTE_NONNUMERIC;

// expat
static PyObject *expat_ParserCreate;

// io
static PyObject *bytesio_ctor, *stringio_ctor;

// time
static PyObject *time_strftime, *time_strptime, *time_localtime;

// operator
static PyObject *op_lt, *op_gt, *op_eq, *op_ne;
static PyObject *op_contains, *op_countOf, *op_indexOf, *op_length_hint;
static PyObject *op_concat, *op_getitem, *op_methodcaller;

// dis
static PyObject *dis_dis;

// locale
static PyObject *locale_strxfrm, *locale_strcoll, *locale_getlocale;

// Handler lambdas (for expat).
static PyObject *noop_handler, *noop_handler_noargs;

static unsigned long gc_counter = 0;

static int initialized = 0;

static void init_parsers(void) {
  if (initialized) return;

  // json
  json_dumps = import_attr("json", "dumps");
  json_JSONEncoder = import_attr("json", "JSONEncoder");

  // csv
  csv_Sniffer = import_attr("csv", "Sniffer");
  csv_writer = import_attr("csv", "writer");
  csv_DictWriter = import_attr("csv", "DictWriter");
  csv_QUOTE_ALL = import_attr("csv", "QUOTE_ALL");
  csv_QUOTE_NONNUMERIC = import_attr("csv", "QUOTE_NONNUMERIC");

  // expat
  expat_ParserCreate = import_attr("xml.parsers.expat", "ParserCreate");

  // io
  bytesio_ctor = import_attr("io", "BytesIO");
  stringio_ctor = import_attr("io", "StringIO");

  // time
  time_strftime = import_attr("time", "strftime");
  time_strptime = import_attr("time", "strptime");
  time_localtime = import_attr("time", "localtime");

  // operator
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

  // dis
  dis_dis = import_attr("dis", "dis");

  // locale
  locale_strxfrm = import_attr("locale", "strxfrm");
  locale_strcoll = import_attr("locale", "strcoll");
  locale_getlocale = import_attr("locale", "getlocale");

  // No-op handler lambdas for expat.
  {
    PyObject *globals = PyDict_New();
    PyDict_SetItemString(globals, "__builtins__", PyEval_GetBuiltins());
    PyObject *r = PyRun_String(
        "_noop = lambda *a: None\n"
        "_noop_noargs = lambda: None\n",
        Py_file_input, globals, globals);
    if (!r) { PyErr_Print(); abort(); }
    Py_DECREF(r);
    noop_handler = PyDict_GetItemString(globals, "_noop");
    Py_INCREF(noop_handler);
    noop_handler_noargs = PyDict_GetItemString(globals, "_noop_noargs");
    Py_INCREF(noop_handler_noargs);
    Py_DECREF(globals);
  }

  // Suppress warnings.
  PyRun_SimpleString("import warnings; warnings.filterwarnings('ignore')");

  assert(!PyErr_Occurred());
  initialized = 1;
}

// ---------------------------------------------------------------------------
// Operations (7 ops).
// ---------------------------------------------------------------------------

// OP_JSON_ENCODE: FDP selects variant — json.dumps(str), json.dumps({str:str}),
// json.dumps([str,str]), or JSONEncoder with options. Exercises the _json
// C acceleration module's encoding paths.
static void op_json_encode(FuzzedDataProvider &fdp) {
  int str_enc = fdp.ConsumeIntegralInRange<int>(0, 3);
  int variant = fdp.ConsumeIntegralInRange<int>(0, 5);
  std::string data = fdp.ConsumeBytesAsString(
      std::min(fdp.remaining_bytes(), (size_t)10000));
  PyRef pystr(fuzz_bytes_to_str(data, str_enc));
  CHECK(pystr);

  switch (variant) {
    case 0: {
      // json.dumps(str)
      PyRef r = PyObject_CallFunction(json_dumps, "O", (PyObject *)pystr);
      break;
    }
    case 1: {
      // json.dumps({str: str})
      PyRef d = PyDict_New();
      CHECK(d);
      PyDict_SetItem(d, pystr, pystr);
      PyRef r = PyObject_CallFunction(json_dumps, "O", (PyObject *)d);
      break;
    }
    case 2: {
      // json.dumps([str, str])
      PyRef lst = PyList_New(2);
      CHECK(lst);
      Py_INCREF((PyObject *)pystr);
      Py_INCREF((PyObject *)pystr);
      PyList_SET_ITEM((PyObject *)lst, 0, (PyObject *)pystr);
      PyList_SET_ITEM((PyObject *)lst, 1, (PyObject *)pystr);
      PyRef r = PyObject_CallFunction(json_dumps, "O", (PyObject *)lst);
      break;
    }
    case 3: {
      // JSONEncoder(ensure_ascii=False).encode(str)
      PyRef kwargs = PyDict_New();
      CHECK(kwargs);
      PyDict_SetItemString(kwargs, "ensure_ascii", Py_False);
      PyRef empty = PyTuple_New(0);
      CHECK(empty);
      PyRef enc = PyObject_Call(json_JSONEncoder, empty, kwargs);
      CHECK(enc);
      PyRef r = PyObject_CallMethod(enc, "encode", "O", (PyObject *)pystr);
      break;
    }
    case 4: {
      // JSONEncoder(ensure_ascii=True).encode(str)
      PyRef kwargs = PyDict_New();
      CHECK(kwargs);
      PyDict_SetItemString(kwargs, "ensure_ascii", Py_True);
      PyRef empty = PyTuple_New(0);
      CHECK(empty);
      PyRef enc = PyObject_Call(json_JSONEncoder, empty, kwargs);
      CHECK(enc);
      PyRef r = PyObject_CallMethod(enc, "encode", "O", (PyObject *)pystr);
      break;
    }
    case 5: {
      // JSONEncoder(sort_keys=True, indent=2, ensure_ascii=False).encode({s:s})
      PyRef kwargs = PyDict_New();
      CHECK(kwargs);
      PyDict_SetItemString(kwargs, "sort_keys", Py_True);
      PyRef indent = PyLong_FromLong(2);
      CHECK(indent);
      PyDict_SetItemString(kwargs, "indent", indent);
      PyDict_SetItemString(kwargs, "ensure_ascii", Py_False);
      PyRef empty = PyTuple_New(0);
      CHECK(empty);
      PyRef enc = PyObject_Call(json_JSONEncoder, empty, kwargs);
      CHECK(enc);
      PyRef d = PyDict_New();
      CHECK(d);
      PyDict_SetItem(d, pystr, pystr);
      PyRef r = PyObject_CallMethod(enc, "encode", "O", (PyObject *)d);
      break;
    }
  }
  if (PyErr_Occurred()) PyErr_Clear();
}

// OP_CSV_SNIFFER: Call csv.Sniffer().sniff() and .has_header() on fuzz str.
// Exercises the _csv C module's dialect detection paths.
static void op_csv_sniffer(FuzzedDataProvider &fdp) {
  int str_enc = fdp.ConsumeIntegralInRange<int>(0, 3);
  std::string data = fdp.ConsumeBytesAsString(
      std::min(fdp.remaining_bytes(), (size_t)1024));
  PyRef pystr(fuzz_bytes_to_str(data, str_enc));
  CHECK(pystr);

  PyRef sniffer = PyObject_CallFunction(csv_Sniffer, NULL);
  CHECK(sniffer);

  {
    PyRef r = PyObject_CallMethod(sniffer, "sniff", "O", (PyObject *)pystr);
    if (PyErr_Occurred()) PyErr_Clear();
  }
  {
    PyRef r = PyObject_CallMethod(sniffer, "has_header", "O",
                                  (PyObject *)pystr);
    if (PyErr_Occurred()) PyErr_Clear();
  }
}

// OP_CSV_WRITER: FDP selects variant — basic writerow, writerows, tab-delimited,
// DictWriter, QUOTE_ALL, QUOTE_NONNUMERIC. All write to StringIO.
// Exercises the _csv C module's writer paths.
static void op_csv_writer(FuzzedDataProvider &fdp) {
  int str_enc = fdp.ConsumeIntegralInRange<int>(0, 3);
  int variant = fdp.ConsumeIntegralInRange<int>(0, 5);
  std::string data = fdp.ConsumeBytesAsString(
      std::min(fdp.remaining_bytes(), (size_t)10000));
  PyRef pystr(fuzz_bytes_to_str(data, str_enc));
  CHECK(pystr);

  PyRef sio = PyObject_CallFunction(stringio_ctor, NULL);
  CHECK(sio);

  // Split string into words for row data.
  PyRef words = PyObject_CallMethod(pystr, "split", NULL);
  if (!words) { PyErr_Clear(); return; }

  // Ensure non-empty.
  if (PyList_Size(words) == 0) {
    PyRef empty = PyUnicode_FromString("");
    PyList_Append(words, empty);
  }

  switch (variant) {
    case 0: {
      // Basic writerow.
      PyRef w = PyObject_CallFunction(csv_writer, "O", (PyObject *)sio);
      CHECK(w);
      PyRef r = PyObject_CallMethod(w, "writerow", "O", (PyObject *)words);
      break;
    }
    case 1: {
      // writerows with lines.
      PyRef lines = PyObject_CallMethod(pystr, "splitlines", NULL);
      if (!lines) { PyErr_Clear(); break; }
      PyRef rows = PyList_New(0);
      CHECK(rows);
      Py_ssize_t nlines = PyList_Size(lines);
      for (Py_ssize_t i = 0; i < nlines && i < 20; i++) {
        PyObject *line = PyList_GetItem(lines, i);
        PyRef lwords = PyObject_CallMethod(line, "split", NULL);
        if (!lwords) { PyErr_Clear(); continue; }
        if (PyList_Size(lwords) == 0) {
          PyRef e = PyUnicode_FromString("");
          PyList_Append(lwords, e);
        }
        PyList_Append(rows, lwords);
      }
      PyRef w = PyObject_CallFunction(csv_writer, "O", (PyObject *)sio);
      CHECK(w);
      PyRef r = PyObject_CallMethod(w, "writerows", "O", (PyObject *)rows);
      break;
    }
    case 2: {
      // Tab-delimited.
      PyRef kwargs = PyDict_New();
      CHECK(kwargs);
      PyRef delim = PyUnicode_FromString("\t");
      CHECK(delim);
      PyDict_SetItemString(kwargs, "delimiter", delim);
      PyRef args = PyTuple_Pack(1, (PyObject *)sio);
      CHECK(args);
      PyRef w = PyObject_Call(csv_writer, args, kwargs);
      CHECK(w);
      PyRef r = PyObject_CallMethod(w, "writerow", "O", (PyObject *)words);
      break;
    }
    case 3: {
      // DictWriter.
      Py_ssize_t nwords = PyList_Size(words);
      Py_ssize_t nfields = nwords < 8 ? nwords : 8;
      if (nfields == 0) nfields = 1;
      PyRef fieldnames = PyList_GetSlice(words, 0, nfields);
      CHECK(fieldnames);
      PyRef kwargs = PyDict_New();
      CHECK(kwargs);
      PyDict_SetItemString(kwargs, "fieldnames", fieldnames);
      PyRef args = PyTuple_Pack(1, (PyObject *)sio);
      CHECK(args);
      PyRef dw = PyObject_Call(csv_DictWriter, args, kwargs);
      CHECK(dw);
      PyRef wh = PyObject_CallMethod(dw, "writeheader", NULL);
      if (PyErr_Occurred()) PyErr_Clear();
      // Build row dict.
      PyRef row = PyDict_New();
      CHECK(row);
      for (Py_ssize_t i = 0; i < nfields; i++) {
        PyObject *fn = PyList_GetItem(fieldnames, i);
        PyDict_SetItem(row, fn, pystr);
      }
      PyRef wr = PyObject_CallMethod(dw, "writerow", "O", (PyObject *)row);
      break;
    }
    case 4: {
      // QUOTE_ALL.
      PyRef kwargs = PyDict_New();
      CHECK(kwargs);
      PyDict_SetItemString(kwargs, "quoting", csv_QUOTE_ALL);
      PyRef args = PyTuple_Pack(1, (PyObject *)sio);
      CHECK(args);
      PyRef w = PyObject_Call(csv_writer, args, kwargs);
      CHECK(w);
      PyRef r = PyObject_CallMethod(w, "writerow", "O", (PyObject *)words);
      break;
    }
    case 5: {
      // QUOTE_NONNUMERIC.
      PyRef kwargs = PyDict_New();
      CHECK(kwargs);
      PyDict_SetItemString(kwargs, "quoting", csv_QUOTE_NONNUMERIC);
      PyRef args = PyTuple_Pack(1, (PyObject *)sio);
      CHECK(args);
      PyRef w = PyObject_Call(csv_writer, args, kwargs);
      CHECK(w);
      PyRef r = PyObject_CallMethod(w, "writerow", "O", (PyObject *)words);
      break;
    }
  }
  if (PyErr_Occurred()) PyErr_Clear();

  // Read result.
  PyRef val = PyObject_CallMethod(sio, "getvalue", NULL);
  if (PyErr_Occurred()) PyErr_Clear();
}

// OP_EXPAT: FDP selects encoding and handler setup, then Parse or ParseFile.
// Exercises the pyexpat C module's XML parsing paths.
static void op_expat(FuzzedDataProvider &fdp) {
  static const char *kEncodings[] = {"utf-8", "iso-8859-1", NULL};
  int enc_idx = fdp.ConsumeIntegralInRange<int>(0, 2);
  bool use_ns = fdp.ConsumeBool();
  bool set_handlers = fdp.ConsumeBool();
  bool use_parsefile = fdp.ConsumeBool();
  std::string data = fdp.ConsumeBytesAsString(
      std::min(fdp.remaining_bytes(), (size_t)4096));

  // Create parser.
  PyRef parser;
  if (use_ns) {
    PyRef kwargs = PyDict_New();
    CHECK(kwargs);
    PyRef ns_sep = PyUnicode_FromString(" ");
    CHECK(ns_sep);
    PyDict_SetItemString(kwargs, "namespace_separator", ns_sep);
    PyRef empty = PyTuple_New(0);
    CHECK(empty);
    parser = PyRef(PyObject_Call(expat_ParserCreate, empty, kwargs));
  } else if (kEncodings[enc_idx]) {
    parser = PyRef(PyObject_CallFunction(expat_ParserCreate, "s",
                                         kEncodings[enc_idx]));
  } else {
    parser = PyRef(PyObject_CallFunction(expat_ParserCreate, NULL));
  }
  CHECK(parser);

  // Set handlers.
  if (set_handlers) {
    PyObject_SetAttrString(parser, "StartElementHandler", noop_handler);
    PyObject_SetAttrString(parser, "EndElementHandler", noop_handler);
    PyObject_SetAttrString(parser, "CharacterDataHandler", noop_handler);
    PyObject_SetAttrString(parser, "ProcessingInstructionHandler",
                           noop_handler);
    PyObject_SetAttrString(parser, "CommentHandler", noop_handler);
    PyObject_SetAttrString(parser, "StartCdataSectionHandler",
                           noop_handler_noargs);
    PyObject_SetAttrString(parser, "EndCdataSectionHandler",
                           noop_handler_noargs);
  }

  PyRef pydata = PyBytes_FromStringAndSize(Y(data));
  CHECK(pydata);

  if (use_parsefile) {
    // ParseFile(BytesIO(data)).
    PyRef bio = PyObject_CallFunction(bytesio_ctor, "O", (PyObject *)pydata);
    CHECK(bio);
    PyRef r = PyObject_CallMethod(parser, "ParseFile", "O", (PyObject *)bio);
  } else {
    // Parse(data, True).
    PyRef r = PyObject_CallMethod(parser, "Parse", "Oi",
                                  (PyObject *)pydata, 1);
  }
  if (PyErr_Occurred()) PyErr_Clear();

  // Optionally GetInputContext.
  if (data.size() % 2 == 0) {
    PyRef ctx = PyObject_CallMethod(parser, "GetInputContext", NULL);
    if (PyErr_Occurred()) PyErr_Clear();
  }
}

// OP_TIME: FDP selects variant — strftime with fuzz format, strptime with
// fuzz input, or strptime with fuzz format. Exercises the time C module.
static void op_time(FuzzedDataProvider &fdp) {
  int str_enc = fdp.ConsumeIntegralInRange<int>(0, 3);
  int variant = fdp.ConsumeIntegralInRange<int>(0, 2);
  std::string data = fdp.ConsumeBytesAsString(
      std::min(fdp.remaining_bytes(), (size_t)10000));
  PyRef pystr(fuzz_bytes_to_str(data, str_enc));
  CHECK(pystr);

  switch (variant) {
    case 0: {
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
    case 1: {
      // time.strptime(str, '%Y-%m-%d %H:%M:%S')
      PyRef r = PyObject_CallFunction(time_strptime, "Os",
                                      (PyObject *)pystr,
                                      "%Y-%m-%d %H:%M:%S");
      break;
    }
    case 2: {
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

// OP_OPERATOR: FDP selects operator variant — comparisons, sequence ops,
// concat, getitem, methodcaller. Exercises the _operator C module.
static void op_operator(FuzzedDataProvider &fdp) {
  int variant = fdp.ConsumeIntegralInRange<int>(0, 5);
  std::string data = fdp.ConsumeRemainingBytesAsString();

  PyRef pydata = PyBytes_FromStringAndSize(Y(data));
  CHECK(pydata);

  switch (variant) {
    case 0: {
      // Comparisons: lt/gt/eq/ne(data, data[::-1])
      PyRef rev = PyObject_CallMethod(pydata, "__class__", NULL);
      // Build reversed bytes.
      std::string rdata(data.rbegin(), data.rend());
      PyRef pyrev = PyBytes_FromStringAndSize(Y(rdata));
      CHECK(pyrev);
      {
        PyRef r = PyObject_CallFunction(op_lt, "OO",
                                        (PyObject *)pydata, (PyObject *)pyrev);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        PyRef r = PyObject_CallFunction(op_gt, "OO",
                                        (PyObject *)pydata, (PyObject *)pyrev);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        PyRef r = PyObject_CallFunction(op_eq, "OO",
                                        (PyObject *)pydata, (PyObject *)pydata);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        PyRef empty = PyBytes_FromStringAndSize("", 0);
        CHECK(empty);
        PyRef r = PyObject_CallFunction(op_ne, "OO",
                                        (PyObject *)pydata, (PyObject *)empty);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      break;
    }
    case 1: {
      // Sequence ops: contains, countOf, indexOf, length_hint
      if (data.empty()) break;
      PyRef byte_val = PyLong_FromLong((unsigned char)data[0]);
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
    case 2: {
      // concat(data, data)
      PyRef r = PyObject_CallFunction(op_concat, "OO",
                                      (PyObject *)pydata, (PyObject *)pydata);
      if (PyErr_Occurred()) PyErr_Clear();
      break;
    }
    case 3: {
      // getitem(data, 0) + getitem(data, slice)
      if (data.empty()) break;
      PyRef zero = PyLong_FromLong(0);
      CHECK(zero);
      {
        PyRef r = PyObject_CallFunction(op_getitem, "OO",
                                        (PyObject *)pydata, (PyObject *)zero);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        PyRef half = PyLong_FromLong(data.size() / 2);
        CHECK(half);
        PyRef sl = PySlice_New(zero, half, NULL);
        CHECK(sl);
        PyRef r = PyObject_CallFunction(op_getitem, "OO",
                                        (PyObject *)pydata, (PyObject *)sl);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      break;
    }
    case 4: {
      // methodcaller('upper')(str) + methodcaller('encode', 'utf-8')(str)
      int str_enc = data.size() > 0 ? data[0] & 3 : 0;
      PyRef pystr(fuzz_bytes_to_str(data, str_enc));
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
    case 5: {
      // contains on bytes with slice
      if (data.empty()) break;
      PyRef first = PyBytes_FromStringAndSize(data.data(), 1);
      CHECK(first);
      PyRef r = PyObject_CallFunction(op_contains, "OO",
                                      (PyObject *)pydata, (PyObject *)first);
      if (PyErr_Occurred()) PyErr_Clear();
      break;
    }
  }
}

// OP_DIS_LOCALE: FDP selects — dis.dis(compile(str)), locale.strxfrm(str),
// locale.strcoll(str), or locale.getlocale(). Exercises _opcode via dis
// and _locale C module.
static void op_dis_locale(FuzzedDataProvider &fdp) {
  int str_enc = fdp.ConsumeIntegralInRange<int>(0, 3);
  int variant = fdp.ConsumeIntegralInRange<int>(0, 3);
  std::string data = fdp.ConsumeBytesAsString(
      std::min(fdp.remaining_bytes(), (size_t)10000));
  PyRef pystr(fuzz_bytes_to_str(data, str_enc));
  CHECK(pystr);

  switch (variant) {
    case 0: {
      // dis.dis(compile(str, '<f>', 'exec'))
      Py_ssize_t slen = PyUnicode_GET_LENGTH(pystr);
      PyObject *src = slen > 0 ? (PyObject *)pystr : NULL;
      if (!src) {
        PyRef def_src = PyUnicode_FromString("pass");
        CHECK(def_src);
        src = def_src;
        Py_INCREF(src);
      } else {
        Py_INCREF(src);
      }
      PyRef code = PyRef(Py_CompileString(
          PyUnicode_AsUTF8(src), "<f>", Py_file_input));
      Py_DECREF(src);
      if (!code) { PyErr_Clear(); break; }
      // Capture dis output to StringIO.
      PyRef sio = PyObject_CallFunction(stringio_ctor, NULL);
      CHECK(sio);
      PyRef kwargs = PyDict_New();
      CHECK(kwargs);
      PyDict_SetItemString(kwargs, "file", sio);
      PyRef args = PyTuple_Pack(1, (PyObject *)code);
      CHECK(args);
      PyRef r = PyObject_Call(dis_dis, args, kwargs);
      if (PyErr_Occurred()) PyErr_Clear();
      break;
    }
    case 1: {
      // locale.strxfrm(str)
      PyRef r = PyObject_CallFunction(locale_strxfrm, "O", (PyObject *)pystr);
      if (PyErr_Occurred()) PyErr_Clear();
      break;
    }
    case 2: {
      // locale.strcoll(str[:mid], str[mid:])
      Py_ssize_t slen = PyUnicode_GET_LENGTH(pystr);
      Py_ssize_t mid = slen / 2;
      PyRef half1 = PyUnicode_Substring(pystr, 0, mid);
      CHECK(half1);
      PyRef half2 = PyUnicode_Substring(pystr, mid, slen);
      CHECK(half2);
      PyRef r = PyObject_CallFunction(locale_strcoll, "OO",
                                      (PyObject *)half1, (PyObject *)half2);
      if (PyErr_Occurred()) PyErr_Clear();
      break;
    }
    case 3: {
      // locale.getlocale()
      PyRef r = PyObject_CallFunction(locale_getlocale, NULL);
      if (PyErr_Occurred()) PyErr_Clear();
      break;
    }
  }
}

// ---------------------------------------------------------------------------
// Dispatch.
// ---------------------------------------------------------------------------

enum Op {
  OP_JSON_ENCODE,
  OP_CSV_SNIFFER,
  OP_CSV_WRITER,
  OP_EXPAT,
  OP_TIME,
  OP_OPERATOR,
  OP_DIS_LOCALE,
  NUM_OPS
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  assert(Py_IsInitialized());
  init_parsers();
  if (size < 1 || size > 0x10000) return 0;
  if (PyErr_Occurred()) PyErr_Clear();

  FuzzedDataProvider fdp(data, size);
  switch (fdp.ConsumeIntegralInRange<int>(0, NUM_OPS - 1)) {
    case OP_JSON_ENCODE:
      op_json_encode(fdp);
      break;
    case OP_CSV_SNIFFER:
      op_csv_sniffer(fdp);
      break;
    case OP_CSV_WRITER:
      op_csv_writer(fdp);
      break;
    case OP_EXPAT:
      op_expat(fdp);
      break;
    case OP_TIME:
      op_time(fdp);
      break;
    case OP_OPERATOR:
      op_operator(fdp);
      break;
    case OP_DIS_LOCALE:
      op_dis_locale(fdp);
      break;
  }

  if (++gc_counter % kGcInterval == 0) PyGC_Collect();
  return 0;
}
