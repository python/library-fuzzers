from fuzzeddataprovider import FuzzedDataProvider
import json

# Container type constants for build_container
CONTAINER_INT_LIST = 0
CONTAINER_STRING = 1
CONTAINER_DICT = 2
CONTAINER_TUPLE = 3
CONTAINER_FLOAT = 4
CONTAINER_INT = 5

# Encode operation constants for FuzzerRunOne
ENCODE_DEFAULT = 0
ENCODE_ASCII = 1
ENCODE_NON_ASCII = 2
ENCODE_SORTED = 3
ENCODE_INDENTED = 4
ENCODE_CUSTOM = 5


def build_container(fdp):
    ctype = fdp.ConsumeIntInRange(CONTAINER_INT_LIST, CONTAINER_INT)
    if ctype == CONTAINER_INT_LIST:
        n = fdp.ConsumeIntInRange(0, min(fdp.remaining_bytes(), 200))
        return fdp.ConsumeIntList(n, 1)
    elif ctype == CONTAINER_STRING:
        n = (
            fdp.ConsumeIntInRange(1, min(fdp.remaining_bytes(), 1000))
            if fdp.remaining_bytes() > 0
            else 0
        )
        return fdp.ConsumeBytes(n).decode("latin-1") if n > 0 else ""
    elif ctype == CONTAINER_DICT:
        n = fdp.ConsumeIntInRange(0, min(fdp.remaining_bytes(), 50))
        d = {}
        for _ in range(n):
            if fdp.remaining_bytes() == 0:
                break
            kn = fdp.ConsumeIntInRange(1, min(fdp.remaining_bytes(), 20))
            key = fdp.ConsumeBytes(kn).decode("latin-1")
            val = fdp.ConsumeRandomValue()
            d[key] = val
        return d
    elif ctype == CONTAINER_TUPLE:
        n = fdp.ConsumeIntInRange(0, min(fdp.remaining_bytes(), 200))
        return tuple(fdp.ConsumeIntList(n, 1))
    elif ctype == CONTAINER_FLOAT:
        return fdp.ConsumeFloat()
    else:
        return fdp.ConsumeInt(4)


# Fuzzes the _json C module's encoding paths (Modules/_json.c).
# Builds Python containers (int lists, string dicts, tuples, floats)
# from fuzzed data and encodes them with json.dumps() using varied
# options (ensure_ascii, sort_keys, indent) and custom JSONEncoder
# settings (separators, allow_nan, default handler).
def FuzzerRunOne(FuzzerInput):
    if len(FuzzerInput) < 1 or len(FuzzerInput) > 0x100000:
        return
    fdp = FuzzedDataProvider(FuzzerInput)
    target = fdp.ConsumeIntInRange(ENCODE_DEFAULT, ENCODE_CUSTOM)
    try:
        obj = build_container(fdp)
        if target == ENCODE_DEFAULT:
            json.dumps(obj)
        elif target == ENCODE_ASCII:
            json.dumps(obj, ensure_ascii=True)
        elif target == ENCODE_NON_ASCII:
            json.dumps(obj, ensure_ascii=False)
        elif target == ENCODE_SORTED:
            json.dumps(obj, sort_keys=True)
        elif target == ENCODE_INDENTED:
            indent = fdp.ConsumeIntInRange(0, 8)
            json.dumps(obj, indent=indent)
        else:
            enc = json.JSONEncoder(
                ensure_ascii=fdp.ConsumeBool(),
                sort_keys=fdp.ConsumeBool(),
                indent=fdp.ConsumeIntInRange(0, 4) if fdp.ConsumeBool() else None,
            )
            enc.encode(obj)
    except (ValueError, TypeError, RecursionError, OverflowError):
        pass
    except Exception:
        pass
