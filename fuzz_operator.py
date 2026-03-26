from fuzz_dp import FuzzedDataProvider
import operator

MAX_LIST_SIZE = 50  # cap on generated list/sequence sizes to avoid OOM

# Top-level fuzzer operation targets
OP_COMPARISONS = 0
OP_ARITHMETIC = 1
OP_UNARY = 2
OP_SEQUENCE = 3
OP_ITEMGETTER = 4
OP_ATTRGETTER = 5
OP_METHODCALLER = 6

# Sequence operation targets
SEQ_CONTAINS = 0
SEQ_COUNT_OF = 1
SEQ_INDEX_OF = 2
SEQ_GETITEM = 3
SEQ_CONCAT = 4
SEQ_SETITEM = 5
SEQ_DELITEM = 6
SEQ_LENGTH_HINT = 7

def op_comparisons(fdp):
    a = fdp.ConsumeRandomValue()
    b = fdp.ConsumeRandomValue()
    ops = [operator.lt, operator.le, operator.gt, operator.ge,
           operator.eq, operator.ne]
    op = fdp.PickValueInList(ops)
    op(a, b)

def op_arithmetic(fdp):
    a = fdp.ConsumeInt(4)
    b = fdp.ConsumeInt(4)
    ops = [operator.add, operator.sub, operator.mul, operator.mod,
           operator.floordiv, operator.truediv, operator.pow,
           operator.lshift, operator.rshift,
           operator.and_, operator.or_, operator.xor]
    op = fdp.PickValueInList(ops)
    if op == operator.pow and isinstance(b, (int, float)):
        b = b % 20 if isinstance(b, int) else b
    if op in (operator.lshift, operator.rshift) and isinstance(b, int):
        b = abs(b) % 64
    op(a, b)

def op_unary(fdp):
    a = fdp.ConsumeRandomValue()
    ops = [operator.neg, operator.pos, operator.abs, operator.invert,
           operator.index]
    op = fdp.PickValueInList(ops)
    op(a)

def op_sequence(fdp):
    n = fdp.ConsumeIntInRange(1, min(fdp.remaining_bytes(), 100))
    lst = fdp.ConsumeIntList(n, 1)
    target = fdp.ConsumeIntInRange(SEQ_CONTAINS, SEQ_LENGTH_HINT)
    if target == SEQ_CONTAINS:
        operator.contains(lst, fdp.ConsumeInt(1))
    elif target == SEQ_COUNT_OF:
        operator.countOf(lst, fdp.ConsumeInt(1))
    elif target == SEQ_INDEX_OF:
        try:
            operator.indexOf(lst, fdp.ConsumeInt(1))
        except ValueError:
            pass
    elif target == SEQ_GETITEM:
        idx = fdp.ConsumeIntInRange(0, max(len(lst) - 1, 0))
        operator.getitem(lst, idx)
    elif target == SEQ_CONCAT:
        operator.concat(lst, fdp.ConsumeIntList(fdp.ConsumeIntInRange(0, MAX_LIST_SIZE), 1))
    elif target == SEQ_SETITEM:
        idx = fdp.ConsumeIntInRange(0, max(len(lst) - 1, 0))
        operator.setitem(lst, idx, fdp.ConsumeInt(1))
    elif target == SEQ_DELITEM:
        idx = fdp.ConsumeIntInRange(0, max(len(lst) - 1, 0))
        operator.delitem(lst, idx)
    elif target == SEQ_LENGTH_HINT:
        operator.length_hint(lst)

def op_itemgetter(fdp):
    n = fdp.ConsumeIntInRange(1, MAX_LIST_SIZE)
    lst = fdp.ConsumeIntList(n, 1)
    if not lst:
        return
    num_keys = fdp.ConsumeIntInRange(1, len(lst))
    keys = [fdp.ConsumeIntInRange(0, len(lst) - 1) for _ in range(num_keys)]
    getter = operator.itemgetter(*keys) if len(keys) > 1 else operator.itemgetter(keys[0])
    getter(lst)

def op_attrgetter(fdp):
    class Obj:
        pass
    obj = Obj()
    attrs = ['x', 'y', 'z', 'w']
    for a in attrs:
        setattr(obj, a, fdp.ConsumeInt(1))
    num_attrs = fdp.ConsumeIntInRange(1, len(attrs))
    chosen = [fdp.PickValueInList(attrs) for _ in range(num_attrs)]
    getter = operator.attrgetter(*chosen) if len(chosen) > 1 else operator.attrgetter(chosen[0])
    getter(obj)

def op_methodcaller(fdp):
    s = fdp.ConsumeUnicode(fdp.ConsumeIntInRange(1, 100))
    methods = ['upper', 'lower', 'strip', 'title', 'swapcase']
    method = fdp.PickValueInList(methods)
    caller = operator.methodcaller(method)
    caller(s)

# Fuzzes the _operator C module (Modules/_operator.c). Exercises
# comparison operators (lt/le/gt/ge/eq/ne), arithmetic operators
# (add/sub/mul/mod/div/pow/shifts/bitwise), unary operators
# (neg/pos/abs/invert/index), sequence operations (contains/countOf/
# indexOf/getitem/concat/setitem/delitem/length_hint), and the
# itemgetter, attrgetter, and methodcaller helpers.
def FuzzerRunOne(FuzzerInput):
    if len(FuzzerInput) < 1 or len(FuzzerInput) > 0x10000:
        return
    fdp = FuzzedDataProvider(FuzzerInput)
    op = fdp.ConsumeIntInRange(OP_COMPARISONS, OP_METHODCALLER)
    try:
        if op == OP_COMPARISONS:
            op_comparisons(fdp)
        elif op == OP_ARITHMETIC:
            op_arithmetic(fdp)
        elif op == OP_UNARY:
            op_unary(fdp)
        elif op == OP_SEQUENCE:
            op_sequence(fdp)
        elif op == OP_ITEMGETTER:
            op_itemgetter(fdp)
        elif op == OP_ATTRGETTER:
            op_attrgetter(fdp)
        elif op == OP_METHODCALLER:
            op_methodcaller(fdp)
    except Exception:
        pass
