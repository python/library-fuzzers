from fuzz_dp import FuzzedDataProvider
import time

FORMATS = [
    "%Y-%m-%d", "%Y-%m-%d %H:%M:%S", "%d/%m/%Y", "%m/%d/%Y",
    "%H:%M:%S", "%I:%M %p", "%c", "%x", "%X",
    "%A %B %d, %Y", "%j", "%U", "%W",
]

MAX_STRING_SIZE = 10000  # cap on generated format/input string sizes

STRFTIME_FUZZED_FORMAT = 0
STRPTIME_KNOWN_FORMAT = 1
STRPTIME_FUZZED_FORMAT = 2

# Fuzzes the time C module (Modules/timemodule.c). Exercises
# time.strftime() with fuzz-generated format strings, and
# time.strptime() with both predefined and fuzz-generated format
# strings against fuzzed date/time input strings.
def FuzzerRunOne(FuzzerInput):
    if len(FuzzerInput) < 1 or len(FuzzerInput) > 0x10000:
        return
    fdp = FuzzedDataProvider(FuzzerInput)
    target = fdp.ConsumeIntInRange(STRFTIME_FUZZED_FORMAT, STRPTIME_FUZZED_FORMAT)
    try:
        if target == STRFTIME_FUZZED_FORMAT:
            fmt = fdp.ConsumeUnicode(fdp.ConsumeIntInRange(1, MAX_STRING_SIZE))
            if fmt:
                time.strftime(fmt)
        elif target == STRPTIME_KNOWN_FORMAT:
            fmt = fdp.PickValueInList(FORMATS)
            s = fdp.ConsumeUnicode(fdp.ConsumeIntInRange(1, MAX_STRING_SIZE))
            if s:
                time.strptime(s, fmt)
        elif target == STRPTIME_FUZZED_FORMAT:
            fmt = fdp.ConsumeUnicode(fdp.ConsumeIntInRange(1, MAX_STRING_SIZE))
            s = fdp.ConsumeUnicode(fdp.ConsumeIntInRange(1, MAX_STRING_SIZE))
            if fmt and s:
                time.strptime(s, fmt)
    except Exception:
        pass
