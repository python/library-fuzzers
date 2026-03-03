// fuzz_sqlite3.cpp — Fuzzer for CPython's _sqlite3 C extension module.
//
// This fuzzer exercises the following CPython C extension module via
// its Python API, called through the Python C API from C++:
//
//   _sqlite3            — connect(':memory:'), execute, executemany,
//                          executescript, complete_statement, create_function,
//                          create_aggregate, set_authorizer, create_collation,
//                          Row factory, blobopen, register_adapter
//
// Exercises the _sqlite3 C extension module wrapping the third-party
// SQLite library.
//
// The fuzzer loops 1-6 times (fdp-driven) on a single ':memory:'
// connection.  Each iteration picks one of 25 single-call targets
// covering table creation, insert, select, executemany, executescript,
// complete_statement, create_function, create_aggregate, set_authorizer,
// create_collation, Row factory, blobopen, and register_adapter.
// Because iterations share one connection, the fuzzer naturally chains
// operations (e.g. CREATE_TABLE → INSERT → SET_AUTHORIZER → SELECT).
//
// All module functions and class constructors are imported once during init
// and cached as static PyObject* pointers. An Aggregate helper class is
// defined via PyRun_String at init time.
// PyRef (RAII) prevents reference leaks. Max input size: 64 KB.

#include "fuzz_helpers.h"

static PyObject *sqlite3_connect, *sqlite3_complete_statement;
static PyObject *sqlite3_register_adapter, *sqlite3_Row;
static long sqlite3_SQLITE_OK_val;
static PyObject *sqlite3_Aggregate_cls;

// Cached Python lambdas and helper classes used by op_sqlite3.
// These are created once in init_sqlite3() via run_python_and_get() and
// reused across every fuzzer iteration.  Caching avoids the overhead of
// calling PyRun_String to rebuild them on each invocation, and ensures
// the fuzzer spends its time in _sqlite3 code rather than the compiler.
static PyObject *sqlite3_identity_fn;     // lambda x: x
static PyObject *sqlite3_auth_fn;         // lambda *a: SQLITE_OK
static PyObject *sqlite3_collation_fn;    // lambda a, b: (a > b) - (a < b)
static PyObject *sqlite3_adapt_cls;       // class _AdaptMe
static PyObject *sqlite3_adapter_fn;      // lambda a: str(a.v)

static int initialized = 0;

// init_sqlite3 is a one-time initialization for the sqlite3 fuzzer.
//
// Imports the Python-level sqlite3 module attributes (connect,
// complete_statement, register_adapter, Row, SQLITE_OK) and caches
// them as static PyObject* pointers so they don't need to be looked
// up on every fuzzer iteration.
//
// Also creates the helper Python objects used by op_sqlite3:
//   - _Agg class        (aggregate step/finalize)
//   - identity lambda    (scalar function callback)
//   - auth lambda        (authorizer callback, returns SQLITE_OK)
//   - collation lambda   (three-way string comparison)
//   - _AdaptMe class     (type adaptation target)
//   - adapter lambda     (converts _AdaptMe -> str)
//
// These are built once via run_python_and_get() and held for the
// lifetime of the process.  Called from LLVMFuzzerTestOneInput on
// the first invocation; the `initialized` guard makes it a no-op
// on subsequent calls.
static void init_sqlite3(void) {
  if (initialized) return;

  sqlite3_connect = import_attr("sqlite3", "connect");
  sqlite3_complete_statement = import_attr("sqlite3", "complete_statement");
  sqlite3_register_adapter = import_attr("sqlite3", "register_adapter");
  sqlite3_Row = import_attr("sqlite3", "Row");
  // Fetch the integer value of sqlite3.SQLITE_OK (typically 0).
  // Used to build the authorizer callback that always permits operations.
  {
    PyObject *v = import_attr("sqlite3", "SQLITE_OK");
    sqlite3_SQLITE_OK_val = PyLong_AsLong(v);
    Py_DECREF(v);
  }

  // Aggregate class for conn.create_aggregate("fuzzagg", 1, _Agg).
  // step() collects values; finalize() returns the count.
  // Exercises the _sqlite3 aggregate callback dispatch path.
  sqlite3_Aggregate_cls = run_python_and_get(
      "class _Agg:\n"
      "    def __init__(self): self.vals = []\n"
      "    def step(self, v): self.vals.append(v)\n"
      "    def finalize(self): return len(self.vals)\n",
      "_Agg");

  // Identity function for conn.create_function("fuzzfn", 1, f).
  // Simply returns its argument unchanged.
  // Exercises the _sqlite3 scalar function callback dispatch path.
  sqlite3_identity_fn = run_python_and_get("_f = lambda x: x\n", "_f");

  // Authorizer callback for conn.set_authorizer(f).
  // Accepts any number of args and always returns SQLITE_OK (permit).
  // Exercises the _sqlite3 authorizer callback dispatch path without
  // blocking any SQL operations.
  {
    char buf[80];
    snprintf(buf, sizeof(buf), "_f = lambda *a: %ld\n", sqlite3_SQLITE_OK_val);
    sqlite3_auth_fn = run_python_and_get(buf, "_f");
  }

  // Collation function for conn.create_collation("fuzz", f).
  // Standard three-way comparison: returns -1, 0, or 1.
  // Exercises the _sqlite3 collation callback dispatch path used by
  // ORDER BY ... COLLATE fuzz.
  sqlite3_collation_fn = run_python_and_get(
      "_f = lambda a, b: (a > b) - (a < b)\n", "_f");

  // Adapter class for sqlite3.register_adapter(_AdaptMe, f).
  // A simple wrapper holding a single value .v.
  // Exercises the _sqlite3 type adaptation path: when an _AdaptMe instance
  // is passed as a query parameter, SQLite calls the registered adapter.
  sqlite3_adapt_cls = run_python_and_get(
      "class _AdaptMe:\n"
      "    def __init__(self, v): self.v = v\n",
      "_AdaptMe");

  // Adapter function for sqlite3.register_adapter(_AdaptMe, f).
  // Converts an _AdaptMe instance to a string via str(a.v).
  // Exercises the _sqlite3 adapter lookup and conversion path.
  sqlite3_adapter_fn = run_python_and_get("_f = lambda a: str(a.v)\n", "_f");

  assert(!PyErr_Occurred());
  initialized = 1;
}

// Helper: Create a memory connection with PRAGMA max_page_count=100.
static PyObject *make_sqlite_conn() {
  PyObject *conn = PyObject_CallFunction(sqlite3_connect, "s", ":memory:");
  if (!conn) return NULL;
  PyRef r = PyObject_CallMethod(conn, "execute", "s",
                                "PRAGMA max_page_count=100");
  if (!r) {
    PyErr_Clear();
    Py_DECREF(conn);
    return NULL;
  }
  return conn;
}

// op_sqlite3: connect(':memory:'), then loop 1-6 times (fdp-driven).
// Each iteration FDP selects one of many single-call targets.  Since
// iterations share the same connection, the fuzzer naturally chains
// operations (e.g. CREATE_TABLE → INSERT_PARAM → SELECT_LIKE across
// three iterations).  Each case makes exactly one SQL/API call.
static void op_sqlite3(FuzzedDataProvider &fdp) {
  enum {
    // Basic SQL execution
    EXECUTE,              // conn.execute(fuzz_sql)
    EXECUTESCRIPT,        // conn.executescript(fuzz_sql)
    COMPLETE_STMT,        // sqlite3.complete_statement(fuzz_sql)
    // Table setup
    CREATE_TABLE_TEXT,    // CREATE TABLE t(a TEXT)
    CREATE_TABLE_BLOB,    // CREATE TABLE t(a BLOB)
    CREATE_TABLE_INT,     // CREATE TABLE t(v INTEGER)
    CREATE_TABLE_MULTI,   // CREATE TABLE t(a TEXT, b BLOB)
    CREATE_TABLE_TEXT_INT, // CREATE TABLE t(a TEXT, b INTEGER)
    // Insert operations
    INSERT_TEXT,          // INSERT INTO t VALUES(?) with fuzz text
    INSERT_PARAM,         // INSERT INTO t VALUES(?,?) with text + blob
    INSERT_ADAPTED,       // INSERT INTO t VALUES(?) with _AdaptMe obj
    // Bulk insert
    EXECUTEMANY_INT,      // conn.executemany("INSERT INTO t VALUES(?)", rows)
    // Select operations
    SELECT_ALL,           // SELECT * FROM t
    SELECT_LIKE,          // SELECT * FROM t WHERE a LIKE ?
    SELECT_AGGREGATES,    // SELECT count(*), sum(v), avg(v), min(v), max(v) FROM t
    SELECT_ORDERED,       // SELECT * FROM t ORDER BY a COLLATE <name>
    SELECT_VIA_FUNC,      // SELECT <name>(a) FROM t
    SELECT_VIA_AGG,       // SELECT <name>(v) FROM t
    // Feature registration
    CREATE_FUNCTION,      // conn.create_function(fuzz_name, fuzz_narg, ...)
    CREATE_AGGREGATE,     // conn.create_aggregate(fuzz_name, fuzz_narg, ...)
    SET_AUTHORIZER,       // conn.set_authorizer(auth_fn)
    CREATE_COLLATION,     // conn.create_collation(fuzz_name, ...)
    SET_ROW_FACTORY,      // conn.row_factory = sqlite3.Row
    REGISTER_ADAPTER,     // sqlite3.register_adapter(_AdaptMe, ...)
    // Blob I/O
    BLOBOPEN,             // conn.blobopen("main","t","a", rowid)
    NUM_TARGETS
  };

  PyRef conn(make_sqlite_conn());
  CHECK(conn);

  // Track the last-registered fuzz-derived names so that SELECT_VIA_FUNC,
  // SELECT_VIA_AGG, and SELECT_ORDERED can reference whatever was registered
  // by an earlier iteration's CREATE_FUNCTION / CREATE_AGGREGATE /
  // CREATE_COLLATION case.
  std::string func_name, agg_name, collation_name;

  // Helper: consume a fuzz-derived string from fdp.  Only called by cases
  // that actually need string data, so cases like CREATE_TABLE_* and
  // SET_AUTHORIZER don't waste fuzz bytes.
  auto consume_pystr = [&fdp]() -> std::pair<std::string, PyRef> {
    int str_enc = fdp.ConsumeIntegralInRange<int>(0, 3);
    if (fdp.remaining_bytes() == 0)
      return {std::string(), PyRef(nullptr)};
    size_t data_len = fdp.ConsumeIntegralInRange<size_t>(
        1, std::min(fdp.remaining_bytes(), (size_t)10000));
    std::string data = fdp.ConsumeBytesAsString(data_len);
    PyRef pystr(fuzz_bytes_to_str(data, str_enc));
    return {std::move(data), std::move(pystr)};
  };

  // Loop so the fuzzer can chain single-call operations on the same
  // connection across iterations (e.g. CREATE_TABLE_TEXT → INSERT_TEXT
  // → SET_AUTHORIZER → SELECT_ALL).  FDP picks the iteration count (1-6).
  int num_iters = fdp.ConsumeIntegralInRange<int>(1, 6);
  for (int iter = 0; iter < num_iters && fdp.remaining_bytes() > 0; iter++) {
    int target_fn = fdp.ConsumeIntegralInRange<int>(0, NUM_TARGETS - 1);

    switch (target_fn) {
      case EXECUTE: {
        // conn.execute(fuzz_sql) — arbitrary SQL on the live connection.
        auto [data, pystr] = consume_pystr();
        if (!pystr) { PyErr_Clear(); break; }
        PyRef r = PyObject_CallMethod(conn, "execute", "O", (PyObject *)pystr);
        break;
      }
      case EXECUTESCRIPT: {
        // conn.executescript(fuzz_sql) — multi-statement SQL in autocommit.
        auto [data, pystr] = consume_pystr();
        if (!pystr) { PyErr_Clear(); break; }
        Py_ssize_t slen = PyUnicode_GET_LENGTH(pystr);
        if (slen > 0) {
          PyRef r = PyObject_CallMethod(conn, "executescript", "O",
                                        (PyObject *)pystr);
        } else {
          PyRef def = PyUnicode_FromString("SELECT 1;");
          PyRef r = PyObject_CallMethod(conn, "executescript", "O",
                                        (PyObject *)def);
        }
        break;
      }
      case COMPLETE_STMT: {
        // sqlite3.complete_statement(fuzz_sql) — checks for trailing ";".
        auto [data, pystr] = consume_pystr();
        if (!pystr) { PyErr_Clear(); break; }
        Py_ssize_t slen = PyUnicode_GET_LENGTH(pystr);
        if (slen > 0) {
          PyRef r = PyObject_CallFunction(sqlite3_complete_statement, "O",
                                          (PyObject *)pystr);
        } else {
          PyRef def = PyUnicode_FromString("SELECT 1;");
          PyRef r = PyObject_CallFunction(sqlite3_complete_statement, "O",
                                          (PyObject *)def);
        }
        break;
      }
      case CREATE_TABLE_TEXT: {
        // CREATE TABLE t(a TEXT) — single text column.
        PyRef r = PyObject_CallMethod(conn, "execute", "s",
                                      "CREATE TABLE t(a TEXT)");
        break;
      }
      case CREATE_TABLE_BLOB: {
        // CREATE TABLE t(a BLOB) — single blob column.
        PyRef r = PyObject_CallMethod(conn, "execute", "s",
                                      "CREATE TABLE t(a BLOB)");
        break;
      }
      case CREATE_TABLE_INT: {
        // CREATE TABLE t(v INTEGER) — single integer column.
        PyRef r = PyObject_CallMethod(conn, "execute", "s",
                                      "CREATE TABLE t(v INTEGER)");
        break;
      }
      case CREATE_TABLE_MULTI: {
        // CREATE TABLE t(a TEXT, b BLOB) — text + blob columns.
        PyRef r = PyObject_CallMethod(conn, "execute", "s",
                                      "CREATE TABLE t(a TEXT, b BLOB)");
        break;
      }
      case CREATE_TABLE_TEXT_INT: {
        // CREATE TABLE t(a TEXT, b INTEGER) — text + integer columns.
        PyRef r = PyObject_CallMethod(conn, "execute", "s",
                                      "CREATE TABLE t(a TEXT, b INTEGER)");
        break;
      }
      case INSERT_TEXT: {
        // INSERT INTO t VALUES(?) — bind fuzz text as a parameter.
        auto [data, pystr] = consume_pystr();
        if (!pystr) { PyErr_Clear(); break; }
        PyRef params = PyTuple_Pack(1, (PyObject *)pystr);
        CHECK(params);
        PyRef r = PyObject_CallMethod(conn, "execute", "sO",
                                      "INSERT INTO t VALUES(?)",
                                      (PyObject *)params);
        break;
      }
      case INSERT_PARAM: {
        // INSERT INTO t VALUES(?,?) — bind fuzz text + fuzz bytes.
        auto [data, pystr] = consume_pystr();
        if (!pystr) { PyErr_Clear(); break; }
        PyRef pydata = PyBytes_FromStringAndSize(data.data(), data.size());
        CHECK(pydata);
        PyRef params = PyTuple_Pack(2, (PyObject *)pystr, (PyObject *)pydata);
        CHECK(params);
        PyRef r = PyObject_CallMethod(conn, "execute", "sO",
                                      "INSERT INTO t VALUES(?, ?)",
                                      (PyObject *)params);
        break;
      }
      case INSERT_ADAPTED: {
        // INSERT INTO t VALUES(?) — bind an _AdaptMe(fuzz_substr) object.
        // Requires REGISTER_ADAPTER to have run earlier on this connection
        // for the adapter to fire; otherwise sqlite3 raises an error.
        auto [data, pystr] = consume_pystr();
        if (!pystr) { PyErr_Clear(); break; }
        Py_ssize_t sub_len = fdp.ConsumeIntegralInRange<Py_ssize_t>(
            0, PyUnicode_GET_LENGTH(pystr));
        PyRef sub = PyUnicode_Substring(pystr, 0, sub_len);
        if (!sub) { PyErr_Clear(); break; }
        PyRef obj = PyObject_CallFunction(sqlite3_adapt_cls, "O",
                                          (PyObject *)sub);
        if (!obj) { PyErr_Clear(); break; }
        PyRef params = PyTuple_Pack(1, (PyObject *)obj);
        CHECK(params);
        PyRef r = PyObject_CallMethod(conn, "execute", "sO",
                                      "INSERT INTO t VALUES(?)",
                                      (PyObject *)params);
        break;
      }
      case EXECUTEMANY_INT: {
        // conn.executemany("INSERT INTO t VALUES(?)", rows) — bulk insert
        // of integer tuples built from fuzz bytes.
        auto [data, pystr] = consume_pystr();
        PyRef rows = PyList_New(0);
        CHECK(rows);
        size_t limit = fdp.ConsumeIntegralInRange<size_t>(
            0, std::min(data.size(), (size_t)10000));
        for (size_t i = 0; i < limit; i++) {
          PyRef val = PyLong_FromLong((unsigned char)data[i]);
          PyRef tup = PyTuple_Pack(1, (PyObject *)val);
          if (tup) PyList_Append(rows, tup);
        }
        PyRef r = PyObject_CallMethod(conn, "executemany", "sO",
                                      "INSERT INTO t VALUES(?)",
                                      (PyObject *)rows);
        break;
      }
      case SELECT_ALL: {
        // SELECT * FROM t — fetch all rows.
        PyRef cur = PyObject_CallMethod(conn, "execute", "s",
                                        "SELECT * FROM t");
        if (cur) {
          PyRef rows = PyObject_CallMethod(cur, "fetchall", NULL);
        }
        break;
      }
      case SELECT_LIKE: {
        // SELECT * FROM t WHERE a LIKE ? — parameterized LIKE query.
        auto [data, pystr] = consume_pystr();
        if (!pystr) { PyErr_Clear(); break; }
        Py_ssize_t sub_len = fdp.ConsumeIntegralInRange<Py_ssize_t>(
            0, PyUnicode_GET_LENGTH(pystr));
        PyRef sub = PyUnicode_Substring(pystr, 0, sub_len);
        if (!sub) { PyErr_Clear(); break; }
        PyRef params = PyTuple_Pack(1, (PyObject *)sub);
        CHECK(params);
        PyRef r = PyObject_CallMethod(conn, "execute", "sO",
                                      "SELECT * FROM t WHERE a LIKE ?",
                                      (PyObject *)params);
        break;
      }
      case SELECT_AGGREGATES: {
        // SELECT count(*), sum(v), avg(v), min(v), max(v) FROM t.
        PyRef cur = PyObject_CallMethod(conn, "execute", "s",
            "SELECT count(*), sum(v), avg(v), min(v), max(v) FROM t");
        if (cur) {
          PyRef row = PyObject_CallMethod(cur, "fetchone", NULL);
        }
        break;
      }
      case SELECT_ORDERED: {
        // SELECT * FROM t ORDER BY a COLLATE <collation_name>.
        // Uses the name from the last CREATE_COLLATION iteration.
        if (collation_name.empty()) break;
        std::string sql = "SELECT * FROM t ORDER BY a COLLATE \"" +
                          collation_name + "\"";
        PyRef cur = PyObject_CallMethod(conn, "execute", "s", sql.c_str());
        if (cur) {
          PyRef rows = PyObject_CallMethod(cur, "fetchall", NULL);
        }
        break;
      }
      case SELECT_VIA_FUNC: {
        // SELECT <func_name>(a) FROM t — triggers scalar function callback.
        // Uses the name from the last CREATE_FUNCTION iteration.
        if (func_name.empty()) break;
        std::string sql = "SELECT \"" + func_name + "\"(a) FROM t";
        PyRef cur = PyObject_CallMethod(conn, "execute", "s", sql.c_str());
        if (cur) {
          PyRef rows = PyObject_CallMethod(cur, "fetchall", NULL);
        }
        break;
      }
      case SELECT_VIA_AGG: {
        // SELECT <agg_name>(v) FROM t — triggers step()/finalize() callbacks.
        // Uses the name from the last CREATE_AGGREGATE iteration.
        if (agg_name.empty()) break;
        std::string sql = "SELECT \"" + agg_name + "\"(v) FROM t";
        PyRef cur = PyObject_CallMethod(conn, "execute", "s", sql.c_str());
        if (cur) {
          PyRef row = PyObject_CallMethod(cur, "fetchone", NULL);
        }
        break;
      }
      case CREATE_FUNCTION: {
        // conn.create_function(name, narg, identity_fn) — register scalar fn
        // with a fuzz-derived name and argument count.  Exercises _sqlite3
        // create_function name handling and narg validation.
        auto [data, pystr] = consume_pystr();
        if (!pystr) { PyErr_Clear(); break; }
        const char *name = PyUnicode_AsUTF8(pystr);
        if (!name) { PyErr_Clear(); break; }
        int narg = fdp.ConsumeIntegralInRange<int>(-1, 8);
        PyRef r = PyObject_CallMethod(conn, "create_function", "siO",
                                      name, narg, sqlite3_identity_fn);
        if (!r) { PyErr_Clear(); break; }
        func_name.assign(name);
        break;
      }
      case CREATE_AGGREGATE: {
        // conn.create_aggregate(name, narg, _Agg) — register aggregate fn
        // with a fuzz-derived name and argument count.  Exercises _sqlite3
        // create_aggregate name handling and narg validation.
        auto [data, pystr] = consume_pystr();
        if (!pystr) { PyErr_Clear(); break; }
        const char *name = PyUnicode_AsUTF8(pystr);
        if (!name) { PyErr_Clear(); break; }
        int narg = fdp.ConsumeIntegralInRange<int>(-1, 8);
        PyRef r = PyObject_CallMethod(conn, "create_aggregate", "siO",
                                      name, narg, sqlite3_Aggregate_cls);
        if (!r) { PyErr_Clear(); break; }
        agg_name.assign(name);
        break;
      }
      case SET_AUTHORIZER: {
        // conn.set_authorizer(auth_fn) — install authorizer callback.
        // All subsequent SQL on this connection goes through the authorizer.
        PyRef r = PyObject_CallMethod(conn, "set_authorizer", "O",
                                      sqlite3_auth_fn);
        break;
      }
      case CREATE_COLLATION: {
        // conn.create_collation(name, collation_fn) — register collation
        // with a fuzz-derived name.  Exercises _sqlite3 create_collation
        // name handling.
        auto [data, pystr] = consume_pystr();
        if (!pystr) { PyErr_Clear(); break; }
        const char *name = PyUnicode_AsUTF8(pystr);
        if (!name) { PyErr_Clear(); break; }
        PyRef r = PyObject_CallMethod(conn, "create_collation", "sO",
                                      name, sqlite3_collation_fn);
        if (!r) { PyErr_Clear(); break; }
        collation_name.assign(name);
        break;
      }
      case SET_ROW_FACTORY: {
        // conn.row_factory = sqlite3.Row — switch to Row-based fetch.
        // Subsequent SELECT results on this connection return sqlite3.Row
        // objects instead of plain tuples.
        PyObject_SetAttrString(conn, "row_factory", sqlite3_Row);
        break;
      }
      case REGISTER_ADAPTER: {
        // sqlite3.register_adapter(_AdaptMe, adapter_fn) — global registration.
        PyRef reg = PyObject_CallFunction(sqlite3_register_adapter, "OO",
                                          sqlite3_adapt_cls,
                                          sqlite3_adapter_fn);
        break;
      }
      case BLOBOPEN: {
        // conn.blobopen("main","t","a", rowid) — open incremental I/O handle.
        // Requires a table "t" with a BLOB column "a" and at least one row.
        // Reads the first rowid, opens the blob, then does one read or write
        // (fdp-chosen) before closing.
        PyRef cur = PyObject_CallMethod(conn, "execute", "s",
                                        "SELECT rowid FROM t LIMIT 1");
        if (!cur) { PyErr_Clear(); break; }
        PyRef row = PyObject_CallMethod(cur, "fetchone", NULL);
        if (!row || row.p == Py_None) { PyErr_Clear(); break; }
        PyRef rid = PySequence_GetItem(row, 0);
        CHECK(rid);
        PyRef blob = PyObject_CallMethod(conn, "blobopen", "sssO",
                                         "main", "t", "a", (PyObject *)rid);
        if (!blob) { PyErr_Clear(); break; }
        if (fdp.ConsumeBool()) {
          // Read the blob content.
          PyRef rd = PyObject_CallMethod(blob, "read", NULL);
        } else {
          // Write fuzz-derived bytes into the blob.
          auto [data, pystr] = consume_pystr();
          size_t wr_len = fdp.ConsumeIntegralInRange<size_t>(
              0, std::min(data.size(), (size_t)10000));
          PyRef wr_data = PyBytes_FromStringAndSize(data.data(), wr_len);
          if (wr_data) {
            PyRef wr = PyObject_CallMethod(blob, "write", "O",
                                           (PyObject *)wr_data);
          }
        }
        {
          PyRef cl = PyObject_CallMethod(blob, "close", NULL);
        }
        break;
      }
    }
    if (PyErr_Occurred()) PyErr_Clear();
  } // end loop

  PyRef cl = PyObject_CallMethod(conn, "close", NULL);
  if (PyErr_Occurred()) PyErr_Clear();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  assert(Py_IsInitialized());
  init_sqlite3();
  if (size < 1 || size > 0x10000) return 0;
  if (PyErr_Occurred()) PyErr_Clear();

  FuzzedDataProvider fdp(data, size);
  op_sqlite3(fdp);
  return 0;
}
