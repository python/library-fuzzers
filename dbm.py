from fuzzeddataprovider import FuzzedDataProvider
import os
import dbm
import tempfile

OP_STORE = 0
OP_GET = 1
OP_LIST_KEYS = 2
OP_DELETE = 3
OP_ITERATE = 4


# Fuzzes the _gdbm C module (Modules/_gdbmmodule.c).
# Exercises key-value store operations on a temporary GDBM database:
# store, get, key listing, deletion, and iteration with fuzzed
# keys and values.
def FuzzerRunOne(FuzzerInput):
    if len(FuzzerInput) < 1 or len(FuzzerInput) > 0x10000:
        return
    fdp = FuzzedDataProvider(FuzzerInput)
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            dbpath = os.path.join(tmpdir, "fuzzdb")
            with dbm.open(dbpath, "c") as db:
                num_ops = fdp.ConsumeIntInRange(1, 20)
                for _ in range(num_ops):
                    if fdp.remaining_bytes() == 0:
                        break
                    op = fdp.ConsumeIntInRange(OP_STORE, OP_ITERATE)
                    if op == OP_STORE:
                        n = fdp.ConsumeIntInRange(1, min(fdp.remaining_bytes(), 100))
                        key = fdp.ConsumeBytes(n)
                        n2 = (
                            fdp.ConsumeIntInRange(1, min(fdp.remaining_bytes(), 1000))
                            if fdp.remaining_bytes() > 0
                            else 0
                        )
                        val = fdp.ConsumeBytes(n2) if n2 > 0 else b""
                        db[key] = val
                    elif op == OP_GET:
                        n = fdp.ConsumeIntInRange(1, min(fdp.remaining_bytes(), 100))
                        key = fdp.ConsumeBytes(n)
                        _ = db.get(key)
                    elif op == OP_LIST_KEYS:
                        _ = list(db.keys())
                    elif op == OP_DELETE:
                        n = fdp.ConsumeIntInRange(1, min(fdp.remaining_bytes(), 100))
                        key = fdp.ConsumeBytes(n)
                        if key in db:
                            del db[key]
                    elif op == OP_ITERATE:
                        for k in db:
                            _ = db[k]
                            break
    except Exception:
        pass
