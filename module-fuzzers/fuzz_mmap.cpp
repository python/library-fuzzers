// fuzz_mmap.cpp — Fuzzer for CPython's mmap C extension module.
//
// This fuzzer exercises the following CPython C extension module via
// its Python API, called through the Python C API from C++:
//
//   mmap                — anonymous mmap: write, find, rfind, read, readline,
//                          seek, resize, move, getitem, setitem, flush, size,
//                          tell, close
//
// All module functions are imported once during init and cached as static
// PyObject* pointers. PyRef (RAII) prevents reference leaks.
// Max input size: 64 KB.

#include "fuzz_helpers.h"

static PyObject *mmap_mmap;

static int initialized = 0;

static void init_mmap(void) {
  if (initialized) return;

  mmap_mmap = import_attr("mmap", "mmap");
  assert(!PyErr_Occurred());
  initialized = 1;
}

// op_mmap: Create anonymous mmap, write data.
// The fuzzer then selects the target.
// Exercises the mmap C module's core operations.
static void op_mmap(FuzzedDataProvider &fdp) {
  enum { FIND_RFIND, READ_READLINE, RESIZE_MOVE, GETITEM_SETITEM, FLUSH_SIZE_TELL, READ_ALL, NUM_TARGETS };
  int target_fn = fdp.ConsumeIntegralInRange<int>(0, NUM_TARGETS - 1);
  if (fdp.remaining_bytes() == 0) return;
  size_t data_len = fdp.ConsumeIntegralInRange<size_t>(
      1, std::min(fdp.remaining_bytes(), (size_t)10000));
  std::string data = fdp.ConsumeBytesAsString(data_len);
  if (data.empty()) data.push_back('\0');

  // mmap(-1, size)
  Py_ssize_t map_size = data.size();
  PyRef mm = PyObject_CallFunction(mmap_mmap, "in", -1, map_size);
  CHECK(mm);

  // First write data and seek to 0.
  PyRef pydata = PyBytes_FromStringAndSize(Y(data));
  CHECK(pydata);
  {
    PyRef r = PyObject_CallMethod(mm, "write", "O", (PyObject *)pydata);
    if (!r) { PyErr_Clear();
      PyRef cl = PyObject_CallMethod(mm, "close", NULL);
      if (PyErr_Occurred()) PyErr_Clear();
      return;
    }
  }
  {
    PyRef r = PyObject_CallMethod(mm, "seek", "i", 0);
    if (!r) { PyErr_Clear();
      PyRef cl = PyObject_CallMethod(mm, "close", NULL);
      if (PyErr_Occurred()) PyErr_Clear();
      return;
    }
  }

  // Now call the target method.
  switch (target_fn) {
    case FIND_RFIND: {
      // find + rfind with fuzz-driven pattern and offsets
      long start = fdp.ConsumeIntegralInRange<long>(0, map_size);
      long end = fdp.ConsumeIntegralInRange<long>(start, map_size);
      std::string pat_str = fdp.ConsumeRemainingBytesAsString();
      PyRef pat = PyBytes_FromStringAndSize(pat_str.data(), pat_str.size());
      CHECK(pat);
      {
        PyRef r = PyObject_CallMethod(mm, "find", "Oll",
                                      (PyObject *)pat, start, end);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        PyRef r = PyObject_CallMethod(mm, "rfind", "Oll",
                                      (PyObject *)pat, start, end);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      break;
    }
    case READ_READLINE: {
      // read + readline with fuzz-driven count and seek position
      {
        long n = fdp.ConsumeIntegralInRange<long>(0, map_size);
        PyRef r = PyObject_CallMethod(mm, "read", "l", n);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        long pos = fdp.ConsumeIntegralInRange<long>(0, map_size);
        PyRef sk = PyObject_CallMethod(mm, "seek", "l", pos);
        if (PyErr_Occurred()) PyErr_Clear();
        PyRef r = PyObject_CallMethod(mm, "readline", NULL);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      break;
    }
    case RESIZE_MOVE: {
      // resize + move with fuzz-driven sizes and offsets
      long new_size = fdp.ConsumeIntegralInRange<long>(1, map_size * 4 + 1);
      {
        PyRef r = PyObject_CallMethod(mm, "resize", "l", new_size);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        // After resize, effective size is new_size (if resize succeeded)
        // or map_size (if it failed). Use new_size as upper bound;
        // mmap.move() will raise on out-of-bounds anyway.
        long dest = fdp.ConsumeIntegralInRange<long>(0, new_size - 1);
        long src = fdp.ConsumeIntegralInRange<long>(0, new_size - 1);
        long max_count = new_size - std::max(dest, src);
        long count = max_count > 0
            ? fdp.ConsumeIntegralInRange<long>(0, max_count)
            : 0;
        PyRef r = PyObject_CallMethod(mm, "move", "lll",
                                      dest, src, count);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      break;
    }
    case GETITEM_SETITEM: {
      // getitem + setitem
      {
        PyRef idx = PyLong_FromLong(0);
        CHECK(idx);
        PyRef r = PyObject_GetItem(mm, idx);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        Py_ssize_t n = map_size < 4 ? map_size : 4;
        PyRef start = PyLong_FromLong(0);
        PyRef stop = PyLong_FromLong(n);
        PyRef sl = PySlice_New(start, stop, NULL);
        CHECK(sl);
        PyRef r = PyObject_GetItem(mm, sl);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      if (data.size() > 0) {
        PyRef idx = PyLong_FromLong(0);
        CHECK(idx);
        PyRef val = PyLong_FromLong((unsigned char)data[0]);
        CHECK(val);
        PyObject_SetItem(mm, idx, val);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      break;
    }
    case FLUSH_SIZE_TELL: {
      // flush + size + tell
      {
        PyRef r = PyObject_CallMethod(mm, "flush", NULL);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        PyRef r = PyObject_CallMethod(mm, "size", NULL);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      {
        PyRef r = PyObject_CallMethod(mm, "tell", NULL);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      break;
    }
    case READ_ALL: {
      // read all
      {
        PyRef r = PyObject_CallMethod(mm, "read", NULL);
        if (PyErr_Occurred()) PyErr_Clear();
      }
      break;
    }
  }

  {
    PyRef r = PyObject_CallMethod(mm, "close", NULL);
    if (PyErr_Occurred()) PyErr_Clear();
  }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  assert(Py_IsInitialized());
  init_mmap();
  if (size < 1 || size > 0x10000) return 0;
  if (PyErr_Occurred()) PyErr_Clear();

  FuzzedDataProvider fdp(data, size);
  op_mmap(fdp);

  return 0;
}
