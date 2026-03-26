from fuzz_dp import FuzzedDataProvider
import array

TYPECODES = list('bBhHiIlLqQfd')

# Top-level operation constants for FuzzerRunOne
OP_FROMBYTES = 0
OP_METHODS = 1
OP_SLICE = 2

# Array method operation constants for op_array_methods
METHOD_REVERSE = 0
METHOD_BYTESWAP = 1
METHOD_POP = 2
METHOD_COUNT = 3
METHOD_INDEX = 4
METHOD_INSERT = 5
METHOD_REMOVE = 6
METHOD_TOBYTES = 7

def _consume_array(fdp):
    tc = fdp.PickValueInList(TYPECODES)
    itemsize = array.array(tc).itemsize
    n_items = fdp.ConsumeIntInRange(0, min(fdp.remaining_bytes() // itemsize, 200))
    data = fdp.ConsumeBytes(n_items * itemsize)
    a = array.array(tc)
    a.frombytes(data)
    return a, tc


def op_array_frombytes(fdp):
    a, tc = _consume_array(fdp)
    a.tobytes()
    a.tolist()

def op_array_methods(fdp):
    a, tc = _consume_array(fdp)
    if len(a) == 0:
        return
    num_ops = fdp.ConsumeIntInRange(1, 20)
    for _ in range(num_ops):
        if fdp.remaining_bytes() == 0:
            break
        op = fdp.ConsumeIntInRange(METHOD_REVERSE, METHOD_TOBYTES)
        if op == METHOD_REVERSE:
            a.reverse()
        elif op == METHOD_BYTESWAP:
            a.byteswap()
        elif op == METHOD_POP and len(a) > 0:
            a.pop()
        elif op == METHOD_COUNT and len(a) > 0:
            val = fdp.ConsumeRandomValue()
            a.count(val)
        elif op == METHOD_INDEX and len(a) > 0:
            val = fdp.ConsumeRandomValue()
            try:
                a.index(val)
            except ValueError:
                pass
        elif op == METHOD_INSERT and len(a) > 0:
            idx = fdp.ConsumeIntInRange(0, len(a) - 1)
            val = fdp.ConsumeRandomValue()
            a.insert(idx, val)
        elif op == METHOD_REMOVE and len(a) > 0:
            val = fdp.ConsumeRandomValue()
            try:
                a.remove(val)
            except ValueError:
                pass
        elif op == METHOD_TOBYTES:
            a.tobytes()

def op_array_slice(fdp):
    a, tc = _consume_array(fdp)
    if len(a) < 2:
        return
    start = fdp.ConsumeIntInRange(0, len(a) - 1)
    end = fdp.ConsumeIntInRange(start, len(a))
    _ = a[start:end]
    b = array.array(tc, a[start:end])
    a[start:end] = b

# Fuzzes the array module's C implementation (Modules/arraymodule.c).
# Exercises array construction from raw bytes via frombytes(), element-level
# operations (reverse, byteswap, pop, count, index, insert, remove), and
# slice read/write across all 12 typecodes (b/B/h/H/i/I/l/L/q/Q/f/d).
def FuzzerRunOne(FuzzerInput):
    if len(FuzzerInput) < 1 or len(FuzzerInput) > 0x10000:
        return
    fdp = FuzzedDataProvider(FuzzerInput)
    op = fdp.ConsumeIntInRange(OP_FROMBYTES, OP_SLICE)
    try:
        if op == OP_FROMBYTES:
            op_array_frombytes(fdp)
        elif op == OP_METHODS:
            op_array_methods(fdp)
        elif op == OP_SLICE:
            op_array_slice(fdp)
    except Exception:
        pass
