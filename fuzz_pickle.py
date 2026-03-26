from fuzz_dp import FuzzedDataProvider
import pickle
import io

MAX_CONTAINER_SIZE = 200  # cap on generated container/string sizes to avoid OOM

# Top-level operation constants for FuzzerRunOne dispatch
OP_DUMPS = 0
OP_LOADS = 1
OP_PICKLER = 2
OP_ROUNDTRIP = 3

# Container type constants for build_container
CTYPE_BYTES = 0
CTYPE_STRING = 1
CTYPE_INT_LIST = 2
CTYPE_TUPLE = 3
CTYPE_SET = 4
CTYPE_FROZENSET = 5
CTYPE_BYTEARRAY = 6
CTYPE_DICT = 7

# Unpickler variant constants for op_loads
VARIANT_RESTRICTED = 0
VARIANT_PERSISTENT = 1
VARIANT_RESTRICTED_FIX_IMPORTS = 2

class RestrictedUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        raise pickle.UnpicklingError('restricted')

class PersistentUnpickler(pickle.Unpickler):
    def persistent_load(self, pid):
        return pid
    def find_class(self, module, name):
        raise pickle.UnpicklingError('restricted')

def build_container(fdp, ctype):
    n = fdp.ConsumeIntInRange(0, min(fdp.remaining_bytes(), MAX_CONTAINER_SIZE))
    if ctype == CTYPE_BYTES:
        return fdp.ConsumeBytes(n)
    elif ctype == CTYPE_STRING:
        return fdp.ConsumeUnicode(n)
    elif ctype == CTYPE_INT_LIST:
        return fdp.ConsumeIntList(n, 1)
    elif ctype == CTYPE_TUPLE:
        return tuple(fdp.ConsumeIntList(n, 1))
    elif ctype == CTYPE_SET:
        return set(fdp.ConsumeIntList(n, 1))
    elif ctype == CTYPE_FROZENSET:
        return frozenset(fdp.ConsumeIntList(n, 1))
    elif ctype == CTYPE_BYTEARRAY:
        return bytearray(fdp.ConsumeBytes(n))
    elif ctype == CTYPE_DICT:
        d = {}
        entries = fdp.ConsumeIntInRange(0, min(n, 64))
        for _ in range(entries):
            if fdp.remaining_bytes() == 0:
                break
            kn = fdp.ConsumeIntInRange(1, 20)
            key = fdp.ConsumeUnicode(kn)
            val = fdp.ConsumeRandomValue()
            d[key] = val
        return d
    return fdp.ConsumeBytes(n)

def op_dumps(fdp):
    ctype = fdp.ConsumeIntInRange(CTYPE_BYTES, CTYPE_DICT)
    protocol = fdp.ConsumeIntInRange(0, 5)
    fix_imports = fdp.ConsumeBool()
    obj = build_container(fdp, ctype)
    pickle.dumps(obj, protocol=protocol, fix_imports=fix_imports)

def op_loads(fdp):
    variant = fdp.ConsumeIntInRange(VARIANT_RESTRICTED, VARIANT_RESTRICTED_FIX_IMPORTS)
    data = fdp.ConsumeBytes(fdp.remaining_bytes())
    bio = io.BytesIO(data)
    if variant == VARIANT_RESTRICTED:
        unpickler = RestrictedUnpickler(bio)
    elif variant == VARIANT_PERSISTENT:
        unpickler = PersistentUnpickler(bio)
    else:
        unpickler = RestrictedUnpickler(bio, fix_imports=True, encoding='bytes')
    unpickler.load()

def op_pickler(fdp):
    protocol = fdp.ConsumeIntInRange(0, 5)
    n = fdp.ConsumeIntInRange(1, min(fdp.remaining_bytes(), MAX_CONTAINER_SIZE)) if fdp.remaining_bytes() > 0 else 0
    if n == 0:
        return
    obj1 = fdp.ConsumeIntList(n, 1)
    s = fdp.ConsumeUnicode(fdp.ConsumeIntInRange(0, MAX_CONTAINER_SIZE))
    bio = io.BytesIO()
    p = pickle.Pickler(bio, protocol)
    p.dump(obj1)
    p.clear_memo()
    p.dump(s)
    bio.getvalue()

def op_roundtrip(fdp):
    ctype = fdp.ConsumeIntInRange(CTYPE_BYTES, CTYPE_DICT)
    obj = build_container(fdp, ctype)
    dumped = pickle.dumps(obj)
    pickle.loads(dumped)

# Fuzzes the _pickle C module (Modules/_pickle.c). Exercises pickle.dumps()
# with protocols 0-5 on various container types (bytes, strings, int lists,
# tuples, sets, frozensets, bytearrays, dicts), pickle.loads() with
# restricted and persistent-load unpickler variants, Pickler.dump() with
# memo clearing, and dumps/loads roundtrips.
def FuzzerRunOne(FuzzerInput):
    if len(FuzzerInput) < 1 or len(FuzzerInput) > 0x100000:
        return
    fdp = FuzzedDataProvider(FuzzerInput)
    op = fdp.ConsumeIntInRange(OP_DUMPS, OP_ROUNDTRIP)
    try:
        if op == OP_DUMPS:
            op_dumps(fdp)
        elif op == OP_LOADS:
            op_loads(fdp)
        elif op == OP_PICKLER:
            op_pickler(fdp)
        else:
            op_roundtrip(fdp)
    except Exception:
        pass
