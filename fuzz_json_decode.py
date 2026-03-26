from fuzz_dp import FuzzedDataProvider
import json

LOADS = 0
DECODER_DECODE = 1
DECODER_RAW_DECODE = 2

# Fuzzes the _json C module's decoding paths (Modules/_json.c).
# Exercises json.loads(), JSONDecoder.decode(), and
# JSONDecoder.raw_decode() with fuzzed byte input decoded as latin-1.
def FuzzerRunOne(FuzzerInput):
    if len(FuzzerInput) < 1 or len(FuzzerInput) > 0x100000:
        return
    fdp = FuzzedDataProvider(FuzzerInput)
    target = fdp.ConsumeIntInRange(LOADS, DECODER_RAW_DECODE)
    n = fdp.ConsumeIntInRange(1, min(fdp.remaining_bytes(), 10000)) if fdp.remaining_bytes() > 0 else 0
    if n == 0:
        return
    s = fdp.ConsumeBytes(n).decode('latin-1')
    try:
        if target == LOADS:
            json.loads(s)
        elif target == DECODER_DECODE:
            dec = json.JSONDecoder()
            dec.decode(s)
        elif target == DECODER_RAW_DECODE:
            dec = json.JSONDecoder()
            dec.raw_decode(s)
    except (json.JSONDecodeError, ValueError, RecursionError):
        pass
    except Exception:
        pass
