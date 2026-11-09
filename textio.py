"""Fuzz io.TextIOWrapper over untrusted bytes.

The incremental decoder, readahead buffer, newline normalisation, error
handlers and teardown paths are all C code (Modules/_io/*.c). The input
header selects a C-implemented encoding, an error handler, a newline
mode and a read pattern; only UnicodeDecodeError (the strict handler on
malformed bytes) is expected -- anything else propagates as a finding.
"""
import io

MAX_TEXTIO_TEST_SIZE = 0x100000  # 1 MiB

ENCODINGS = [
    "utf-8",
    "utf-16",
    "utf-16-le",
    "utf-16-be",
    "utf-32",
    "utf-32-le",
    "utf-32-be",
    "latin-1",
]
ERRORS = ["strict", "replace", "ignore", "surrogateescape"]
NEWLINES = ["", "\n", "\r", "\r\n"]


def FuzzerRunOne(FuzzerInput):
    if len(FuzzerInput) < 6 or len(FuzzerInput) > MAX_TEXTIO_TEST_SIZE:
        return
    encoding = ENCODINGS[FuzzerInput[0] % len(ENCODINGS)]
    errors = ERRORS[FuzzerInput[1] % len(ERRORS)]
    newline = NEWLINES[FuzzerInput[2] % len(NEWLINES)]
    op = FuzzerInput[3]
    chunk = 1 + FuzzerInput[4] % 64
    data = FuzzerInput[5:]

    # Only our own constant parameters are used here; a failure would be
    # a bug and is allowed to propagate.
    wrapper = io.TextIOWrapper(
        io.BytesIO(data), encoding=encoding, errors=errors, newline=newline
    )
    try:
        pattern = op % 4
        if pattern == 0:
            wrapper.read()
        elif pattern == 1:
            while wrapper.readline():
                pass
        elif pattern == 2:
            while wrapper.read(chunk):
                pass
        else:
            for _ in wrapper:
                pass
        wrapper.close()
    except UnicodeDecodeError:
        pass
