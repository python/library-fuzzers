"""Fuzz the C unpickler over untrusted bytes.

pickle is the classic "never unpickle untrusted data" surface: the load
loop lives in the C accelerator _pickle.Unpickler. We subclass it only to
disable find_class, so mutated payloads cannot import arbitrary modules or
execute code inside the fuzzer process while every opcode-handling code
path (stack/memo manipulation, string and framing parsing, object
reconstruction of built-in types) stays covered. Invalid streams raise
UnpicklingError/EOFError, and object reconstruction (REDUCE, SETSTATE,
APPEND on built-in containers) can raise arbitrary exceptions -- those are
expected for attacker bytes; memory-safety bugs in the opcode machinery
still crash the sanitiser.
"""
import _pickle
import io

MAX_PICKLE_TEST_SIZE = 0x100000  # 1 MiB


class FuzzerUnpickler(_pickle.Unpickler):
    def find_class(self, module, name):
        raise _pickle.UnpicklingError("find_class is disabled")


def FuzzerRunOne(FuzzerInput):
    if len(FuzzerInput) > MAX_PICKLE_TEST_SIZE:
        return
    try:
        FuzzerUnpickler(io.BytesIO(FuzzerInput)).load()
    except Exception:
        pass
