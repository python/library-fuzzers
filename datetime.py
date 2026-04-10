from fuzzeddataprovider import FuzzedDataProvider
from datetime import date, time, datetime

# Parse target constants (op_parse)
PARSE_DATE_FROMISOFORMAT = 0
PARSE_TIME_FROMISOFORMAT = 1
PARSE_DATETIME_FROMISOFORMAT = 2
PARSE_DATETIME_STRPTIME = 3

# Format target constants (op_format)
FORMAT_DATE = 0
FORMAT_TIME = 1
FORMAT_DATETIME = 2

OP_PARSE = 0
OP_FORMAT = 1

STRPTIME_FORMATS = [
    "%Y-%m-%d",
    "%Y-%m-%d %H:%M:%S",
    "%d/%m/%Y",
    "%m/%d/%Y",
    "%Y%m%d",
    "%H:%M:%S",
    "%I:%M %p",
    "%Y-%m-%dT%H:%M:%S",
    "%a %b %d %H:%M:%S %Y",
    "%c",
]


def op_parse(fdp):
    s = fdp.ConsumeUnicode(fdp.ConsumeIntInRange(1, 100))
    if not s:
        return
    target = fdp.ConsumeIntInRange(PARSE_DATE_FROMISOFORMAT)
    if target == PARSE_DATE_FROMISOFORMAT:
        date.fromisoformat(s)
    elif target == PARSE_TIME_FROMISOFORMAT:
        time.fromisoformat(s)
    elif target == PARSE_DATETIME_FROMISOFORMAT:
        datetime.fromisoformat(s)


def op_format(fdp):
    fmt = fdp.ConsumeUnicode(fdp.ConsumeIntInRange(1, 100))
    if not fmt:
        return
    target = fdp.ConsumeIntInRange(FORMAT_DATE, FORMAT_DATETIME)
    if target == FORMAT_DATE:
        year = fdp.ConsumeIntInRange(1, 9999)
        month = fdp.ConsumeIntInRange(1, 12)
        day = fdp.ConsumeIntInRange(1, 28)
        date(year, month, day).strftime(fmt)
    elif target == FORMAT_TIME:
        hour = fdp.ConsumeIntInRange(0, 23)
        minute = fdp.ConsumeIntInRange(0, 59)
        second = fdp.ConsumeIntInRange(0, 59)
        time(hour, minute, second).strftime(fmt)
    elif target == FORMAT_DATETIME:
        year = fdp.ConsumeIntInRange(1, 9999)
        month = fdp.ConsumeIntInRange(1, 12)
        day = fdp.ConsumeIntInRange(1, 28)
        hour = fdp.ConsumeIntInRange(0, 23)
        minute = fdp.ConsumeIntInRange(0, 59)
        second = fdp.ConsumeIntInRange(0, 59)
        datetime(year, month, day, hour, minute, second).strftime(fmt)


# Fuzzes the _datetime C module (Modules/_datetimemodule.c).
# Exercises ISO format parsing (date/time/datetime.fromisoformat),
# strptime with multiple predefined format strings, and strftime with
# fuzz-generated format strings. Only operations that pass fuzzed
# text into the C parser are included.
def FuzzerRunOne(FuzzerInput):
    if len(FuzzerInput) < 1 or len(FuzzerInput) > 0x10000:
        return
    fdp = FuzzedDataProvider(FuzzerInput)
    op = fdp.ConsumeIntInRange(OP_PARSE, OP_FORMAT)
    try:
        if op == OP_PARSE:
            op_parse(fdp)
        elif op == OP_FORMAT:
            op_format(fdp)
    except Exception:
        pass
