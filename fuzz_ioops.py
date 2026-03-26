from fuzz_dp import FuzzedDataProvider
import os
import io
import tempfile

# Top-level operation constants for FuzzerRunOne dispatch
OP_BYTESIO = 0
OP_TEXTIOWRAPPER = 1
OP_BUFFERED_IO = 2
OP_FILEIO = 3
OP_IO_OPEN = 4
OP_NEWLINE_DECODER = 5
OP_STRINGIO = 6

# Buffered IO target constants for op_buffered_io
BUFFERED_READER = 0
BUFFERED_WRITER = 1
BUFFERED_RANDOM = 2

# Tests BytesIO (Modules/_io/bytesio.c): write, seeked read, readline,
# readinto a pre-allocated buffer, getbuffer for the memoryview path,
# truncate at a fuzzed position, and getvalue.
def op_bytesio(fdp):
    trunc_pos = fdp.ConsumeIntInRange(0, fdp.remaining_bytes())
    data = fdp.ConsumeBytes(fdp.remaining_bytes())
    bio = io.BytesIO()
    bio.write(data)
    bio.seek(0)
    bio.read()
    bio.seek(0)
    bio.readline()
    buf = bytearray(min(len(data), 100))
    bio.seek(0)
    bio.readinto(buf)
    bio.getbuffer()
    bio.truncate(trunc_pos)
    bio.getvalue()

# Tests TextIOWrapper (Modules/_io/textio.c): wraps a BytesIO in a text
# decoder with a fuzzed encoding (utf-8, latin-1, ascii, utf-16) and
# newline mode (None, '', \n, \r, \r\n), then exercises read, readline,
# and detach. Targets the C-level text decoding and newline translation.
def op_textiowrapper(fdp):
    encodings = ['utf-8', 'latin-1', 'ascii', 'utf-16']
    encoding = fdp.PickValueInList(encodings)
    newlines = [None, '', '\n', '\r', '\r\n']
    newline = fdp.PickValueInList(newlines)
    data = fdp.ConsumeBytes(fdp.remaining_bytes())
    bio = io.BytesIO(data)
    wrapper = io.TextIOWrapper(bio, encoding=encoding, errors='replace', newline=newline)
    wrapper.read()
    wrapper.seek(0)
    wrapper.readline()
    wrapper.detach()

# Tests BufferedReader/Writer/Random (Modules/_io/bufferedio.c): picks
# one of the three buffered I/O types and exercises read, write, seek,
# and flush through the C buffering layer over a BytesIO raw stream.
def op_buffered_io(fdp):
    target = fdp.ConsumeIntInRange(BUFFERED_READER, BUFFERED_RANDOM)
    read_size = fdp.ConsumeIntInRange(0, 10000)
    data = fdp.ConsumeBytes(fdp.remaining_bytes())
    if target == BUFFERED_READER:
        raw = io.BytesIO(data)
        br = io.BufferedReader(raw)
        br.read()
    elif target == BUFFERED_WRITER:
        raw = io.BytesIO()
        bw = io.BufferedWriter(raw)
        bw.write(data)
        bw.flush()
    else:
        write_data = fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 10000))
        raw = io.BytesIO(data)
        brw = io.BufferedRandom(raw)
        brw.read(read_size)
        brw.write(write_data)
        brw.seek(0)
        brw.read()

# Tests FileIO (Modules/_io/fileio.c): writes fuzzed data to a temp file
# then reads it back, or reads pre-written data. Exercises the C-level
# file descriptor I/O paths (open, write, read, close).
def op_fileio(fdp):
    do_write = fdp.ConsumeBool()
    data = fdp.ConsumeBytes(fdp.remaining_bytes())
    tmpname = None
    try:
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmpname = tmp.name
            if do_write:
                f = io.FileIO(tmpname, 'w')
                f.write(data)
                f.close()
                f = io.FileIO(tmpname, 'r')
                f.read()
                f.close()
            else:
                tmp.write(data)
                tmp.flush()
                f = io.FileIO(tmpname, 'r')
                f.read()
                f.close()
    finally:
        if tmpname:
            try:
                os.unlink(tmpname)
            except Exception:
                pass

# Tests io.open() (Modules/_io/_iomodule.c): the high-level open function
# that selects the appropriate I/O class based on mode. Writes fuzzed data
# to a temp file then opens it in binary or text mode with error handling.
def op_io_open(fdp):
    modes = ['rb', 'r', 'rb']
    mode = fdp.PickValueInList(modes)
    data = fdp.ConsumeBytes(fdp.remaining_bytes())
    tmpname = None
    try:
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmpname = tmp.name
            tmp.write(data)
            tmp.flush()
        with io.open(tmpname, mode, errors='replace' if 'b' not in mode else None) as f:
            f.read()
    finally:
        if tmpname:
            try:
                os.unlink(tmpname)
            except Exception:
                pass

# Tests IncrementalNewlineDecoder (Modules/_io/textio.c): the C-level
# newline translator that handles \r, \n, \r\n conversion. Exercises
# decode with fuzzed text, then getstate/reset for the state machine.
def op_newline_decoder(fdp):
    translate = fdp.ConsumeBool()
    n = fdp.ConsumeIntInRange(1, min(fdp.remaining_bytes(), 10000)) if fdp.remaining_bytes() > 0 else 0
    if n == 0:
        return
    s = fdp.ConsumeBytes(n).decode('latin-1')
    decoder = io.IncrementalNewlineDecoder(None, translate)
    decoder.decode(s)
    decoder.getstate()
    decoder.reset()

# Tests StringIO (Modules/_io/stringio.c): in-memory text stream.
# Exercises read, readline, seeked write, and getvalue with fuzzed
# Unicode text content.
def op_stringio(fdp):
    n = fdp.ConsumeIntInRange(1, min(fdp.remaining_bytes(), 10000)) if fdp.remaining_bytes() > 0 else 0
    if n == 0:
        return
    s = fdp.ConsumeBytes(n).decode('latin-1')
    sio = io.StringIO(s)
    sio.read()
    sio.seek(0)
    sio.readline()
    sio.seek(0)
    sio.write(s)
    sio.getvalue()

# Fuzzes CPython's I/O C modules (Modules/_io/). Exercises BytesIO
# (write, seek, read, truncate), TextIOWrapper (read, readline, detach
# with varied encodings and newline modes), BufferedReader/Writer/Random,
# FileIO (read and write modes), io.open(), IncrementalNewlineDecoder
# (decode, getstate, reset), and StringIO operations.
def FuzzerRunOne(FuzzerInput):
    if len(FuzzerInput) < 1 or len(FuzzerInput) > 0x100000:
        return
    fdp = FuzzedDataProvider(FuzzerInput)
    op = fdp.ConsumeIntInRange(OP_BYTESIO, OP_STRINGIO)
    try:
        if op == OP_BYTESIO:
            op_bytesio(fdp)
        elif op == OP_TEXTIOWRAPPER:
            op_textiowrapper(fdp)
        elif op == OP_BUFFERED_IO:
            op_buffered_io(fdp)
        elif op == OP_FILEIO:
            op_fileio(fdp)
        elif op == OP_IO_OPEN:
            op_io_open(fdp)
        elif op == OP_NEWLINE_DECODER:
            op_newline_decoder(fdp)
        else:
            op_stringio(fdp)
    except Exception:
        pass
