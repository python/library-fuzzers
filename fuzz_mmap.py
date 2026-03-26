from fuzz_dp import FuzzedDataProvider
import os
import mmap
import tempfile

OP_FIND = 0
OP_RFIND = 1
OP_READ = 2
OP_READLINE = 3
OP_SEEK = 4
OP_GETITEM = 5
OP_WRITE = 6
OP_SETITEM = 7
OP_MOVE = 8
OP_FLUSH = 9

_OP_MAX = OP_FLUSH

# Fuzzes the mmap C module (Modules/mmapmodule.c). Creates a temporary
# file-backed mmap and exercises find, rfind, seek, read, readline,
# getitem, write, setitem, move, and flush operations with fuzzed
# offsets, sizes, and byte content.
def FuzzerRunOne(FuzzerInput):
    if len(FuzzerInput) < 1 or len(FuzzerInput) > 0x10000:
        return
    fdp = FuzzedDataProvider(FuzzerInput)
    init_size = fdp.ConsumeIntInRange(1, min(fdp.remaining_bytes(), 4096)) if fdp.remaining_bytes() > 0 else 0
    if init_size == 0:
        return
    init_data = fdp.ConsumeBytes(init_size)
    tmpname = None
    try:
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmpname = tmp.name
            tmp.write(init_data)
            tmp.flush()

        with open(tmpname, 'r+b') as f:
            mm = mmap.mmap(f.fileno(), 0)
            num_ops = fdp.ConsumeIntInRange(1, 10)
            for _ in range(num_ops):
                if fdp.remaining_bytes() == 0:
                    break
                op = fdp.ConsumeIntInRange(0, _OP_MAX)
                if op == OP_FIND:
                    needle = fdp.ConsumeBytes(fdp.ConsumeIntInRange(1, min(fdp.remaining_bytes(), 20)))
                    mm.find(needle)
                elif op == OP_RFIND:
                    needle = fdp.ConsumeBytes(fdp.ConsumeIntInRange(1, min(fdp.remaining_bytes(), 20)))
                    mm.rfind(needle)
                elif op == OP_READ:
                    mm.seek(0)
                    mm.read(fdp.ConsumeIntInRange(0, len(mm)))
                elif op == OP_READLINE:
                    mm.seek(0)
                    mm.readline()
                elif op == OP_SEEK:
                    pos = fdp.ConsumeIntInRange(0, max(0, len(mm) - 1))
                    mm.seek(pos)
                elif op == OP_GETITEM:
                    if len(mm) > 0:
                        idx = fdp.ConsumeIntInRange(0, len(mm) - 1)
                        _ = mm[idx]
                elif op == OP_WRITE:
                    data = fdp.ConsumeBytes(fdp.ConsumeIntInRange(1, min(fdp.remaining_bytes(), 50)))
                    pos = fdp.ConsumeIntInRange(0, max(0, len(mm) - len(data)))
                    mm.seek(pos)
                    mm.write(data)
                elif op == OP_SETITEM:
                    if len(mm) > 0:
                        idx = fdp.ConsumeIntInRange(0, len(mm) - 1)
                        mm[idx] = fdp.ConsumeInt(1)
                elif op == OP_MOVE:
                    if len(mm) > 1:
                        count = fdp.ConsumeIntInRange(1, len(mm) // 2)
                        src = fdp.ConsumeIntInRange(0, len(mm) - count)
                        dest = fdp.ConsumeIntInRange(0, len(mm) - count)
                        mm.move(dest, src, count)
                elif op == OP_FLUSH:
                    mm.flush()
            mm.close()
    except Exception:
        pass
    finally:
        if tmpname:
            try:
                os.unlink(tmpname)
            except Exception:
                pass
