from fuzz_dp import FuzzedDataProvider
import collections

# Top-level fuzzer dispatch operations
OP_FUZZER_COUNT_ELEMENTS = 0
OP_FUZZER_DEQUE = 1
OP_FUZZER_DEFAULTDICT = 2
OP_FUZZER_ORDERED_DICT = 3

# Deque operations
OP_DEQUE_APPEND = 0
OP_DEQUE_APPENDLEFT = 1
OP_DEQUE_POP = 2
OP_DEQUE_POPLEFT = 3
OP_DEQUE_EXTEND = 4
OP_DEQUE_EXTENDLEFT = 5
OP_DEQUE_ROTATE = 6
OP_DEQUE_REVERSE = 7
OP_DEQUE_COUNT = 8
OP_DEQUE_INDEX = 9
OP_DEQUE_REMOVE = 10
OP_DEQUE_CLEAR = 11
OP_DEQUE_COPY = 12
OP_DEQUE_COMPARE = 13
OP_DEQUE_ITERATE = 14

# Defaultdict operations
OP_DDICT_INCREMENT = 0
OP_DDICT_ACCESS = 1
OP_DDICT_CONTAINS = 2
OP_DDICT_POP = 3

# OrderedDict operations
OP_ODICT_SET = 0
OP_ODICT_POP = 1
OP_ODICT_MOVE_TO_END = 2
OP_ODICT_LIST_KEYS = 3
OP_ODICT_REVERSED = 4
OP_ODICT_POPITEM = 5

# Exercises collections._count_elements(), an internal C helper that counts
# occurrences of each character in a string into a dict. Targets the
# _count_elements C function which has fast-path logic for exact-dict types
# vs dict subclasses.
def op_count_elements(fdp):
    n = fdp.ConsumeIntInRange(1, min(fdp.remaining_bytes(), 10000)) if fdp.remaining_bytes() > 0 else 0
    if n == 0:
        return
    s = fdp.ConsumeBytes(n).decode('latin-1')
    d = {}
    collections._count_elements(d, s)

# Exercises collections.deque with an optional maxlen constraint. Runs a
# sequence of fuzzed operations that exercise the deque's C implementation:
# append/pop from both ends, extend/extendleft with lists, rotate, reverse,
# search (count/index/remove with random-typed values for error path
# coverage), clear, copy, rich comparison against a second deque, and
# iteration via list()/len()/bool().
def op_deque(fdp):
    maxlen = fdp.ConsumeIntInRange(0, 100) if fdp.ConsumeBool() else None
    init_n = fdp.ConsumeIntInRange(0, min(fdp.remaining_bytes(), 50))
    init_data = fdp.ConsumeIntList(init_n, 1)
    dq = collections.deque(init_data, maxlen=maxlen)
    num_ops = fdp.ConsumeIntInRange(1, 30)
    for _ in range(num_ops):
        if fdp.remaining_bytes() == 0:
            break
        op = fdp.ConsumeIntInRange(OP_DEQUE_APPEND, OP_DEQUE_ITERATE)
        if op == OP_DEQUE_APPEND:
            dq.append(fdp.ConsumeRandomValue())
        elif op == OP_DEQUE_APPENDLEFT:
            dq.appendleft(fdp.ConsumeRandomValue())
        elif op == OP_DEQUE_POP and len(dq) > 0:
            dq.pop()
        elif op == OP_DEQUE_POPLEFT and len(dq) > 0:
            dq.popleft()
        elif op == OP_DEQUE_EXTEND:
            n = fdp.ConsumeIntInRange(1, min(fdp.remaining_bytes(), 50))
            dq.extend(fdp.ConsumeIntList(n, 1))
        elif op == OP_DEQUE_EXTENDLEFT:
            n = fdp.ConsumeIntInRange(1, min(fdp.remaining_bytes(), 50))
            dq.extendleft(fdp.ConsumeIntList(n, 1))
        elif op == OP_DEQUE_ROTATE:
            dq.rotate(fdp.ConsumeIntInRange(-10, 10))
        elif op == OP_DEQUE_REVERSE:
            dq.reverse()
        elif op == OP_DEQUE_COUNT:
            dq.count(fdp.ConsumeRandomValue())
        elif op == OP_DEQUE_INDEX and len(dq) > 0:
            try:
                dq.index(fdp.ConsumeRandomValue())
            except ValueError:
                pass
        elif op == OP_DEQUE_REMOVE and len(dq) > 0:
            try:
                dq.remove(fdp.ConsumeRandomValue())
            except ValueError:
                pass
        elif op == OP_DEQUE_CLEAR:
            dq.clear()
        elif op == OP_DEQUE_COPY:
            dq.copy()
        elif op == OP_DEQUE_COMPARE:
            dq2 = collections.deque(fdp.ConsumeIntList(
                fdp.ConsumeIntInRange(0, min(fdp.remaining_bytes(), 20)), 1))
            _ = dq == dq2
            _ = dq < dq2
        elif op == OP_DEQUE_ITERATE:
            _ = list(dq)
            _ = len(dq)
            _ = bool(dq)

# Exercises collections.defaultdict with int as the default factory.
# Runs fuzzed sequences of key increment (triggers __missing__ on new keys),
# key access, containment checks, and pop operations. Keys are fuzzed
# latin-1 strings so the same key may be accessed multiple times, exercising
# both the hit and miss paths in the underlying dict C implementation.
def op_defaultdict(fdp):
    dd = collections.defaultdict(int)
    num_ops = fdp.ConsumeIntInRange(1, 20)
    for _ in range(num_ops):
        if fdp.remaining_bytes() == 0:
            break
        op = fdp.ConsumeIntInRange(OP_DDICT_INCREMENT, OP_DDICT_POP)
        key = fdp.ConsumeBytes(fdp.ConsumeIntInRange(1, 10)).decode('latin-1')
        if op == OP_DDICT_INCREMENT:
            dd[key] += fdp.ConsumeInt(1)
        elif op == OP_DDICT_ACCESS:
            _ = dd[key]
        elif op == OP_DDICT_CONTAINS:
            _ = key in dd
        elif op == OP_DDICT_POP:
            dd.pop(key, None)

# Exercises collections.OrderedDict's C implementation (odictobject.c).
# Runs fuzzed sequences of set (with random-typed values), pop,
# move_to_end (with fuzzed last= direction), key listing, reversed
# iteration, and popitem (with fuzzed last= direction). The key reuse
# from short fuzzed strings exercises the internal linked-list
# reordering logic.
def op_ordered_dict(fdp):
    od = collections.OrderedDict()
    num_ops = fdp.ConsumeIntInRange(1, 20)
    for _ in range(num_ops):
        if fdp.remaining_bytes() == 0:
            break
        op = fdp.ConsumeIntInRange(OP_ODICT_SET, OP_ODICT_POPITEM)
        key = fdp.ConsumeBytes(fdp.ConsumeIntInRange(1, 10)).decode('latin-1')
        if op == OP_ODICT_SET:
            od[key] = fdp.ConsumeRandomValue()
        elif op == OP_ODICT_POP:
            od.pop(key, None)
        elif op == OP_ODICT_MOVE_TO_END:
            od.move_to_end(key, last=fdp.ConsumeBool()) if key in od else None
        elif op == OP_ODICT_LIST_KEYS:
            _ = list(od.keys())
        elif op == OP_ODICT_REVERSED:
            _ = list(reversed(od))
        elif op == OP_ODICT_POPITEM and len(od) > 0:
            od.popitem(last=fdp.ConsumeBool())

# Fuzzes the _collections C module (Modules/_collectionsmodule.c).
# Exercises _count_elements() with fuzzed iterables, deque operations
# (append, pop, extend, rotate, reverse, count, index, remove, copy),
# defaultdict key access patterns, and OrderedDict manipulation
# (set, pop, move_to_end, popitem, reversed iteration).
def FuzzerRunOne(FuzzerInput):
    if len(FuzzerInput) < 1 or len(FuzzerInput) > 0x10000:
        return
    fdp = FuzzedDataProvider(FuzzerInput)
    op = fdp.ConsumeIntInRange(OP_FUZZER_COUNT_ELEMENTS, OP_FUZZER_ORDERED_DICT)
    try:
        if op == OP_FUZZER_COUNT_ELEMENTS:
            op_count_elements(fdp)
        elif op == OP_FUZZER_DEQUE:
            op_deque(fdp)
        elif op == OP_FUZZER_DEFAULTDICT:
            op_defaultdict(fdp)
        else:
            op_ordered_dict(fdp)
    except Exception:
        pass
