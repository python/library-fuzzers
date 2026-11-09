"""Fuzz the C ISO-8601 fast parsers and date/time arithmetic.

date, time and datetime fromisoformat() are implemented in C
(Modules/_datetimemodule.c) and parse attacker-controlled strings.
Two properties are exercised: isoformat() must round-trip through
fromisoformat (documented inverse -- a mismatch is a logic bug and
raises AssertionError), and fuzzed timedelta shifts drive the C
normalisation and overflow-checking paths. Invalid ISO strings are
expected and raise ValueError/TypeError; time objects reject +/- with
TypeError.
"""
from datetime import date, datetime, time, timedelta


def FuzzerRunOne(FuzzerInput):
    if len(FuzzerInput) < 3:
        return
    op = FuzzerInput[0]
    amount = FuzzerInput[1]
    data = FuzzerInput[2:].decode("utf-8", "replace")
    if op % 3 == 0:
        parse = date.fromisoformat
    elif op % 3 == 1:
        parse = time.fromisoformat
    else:
        parse = datetime.fromisoformat
    try:
        parsed = parse(data)
    except (ValueError, TypeError):
        return

    # Round-trip property: fromisoformat is the documented inverse of
    # isoformat(), for all three types.
    reparsed = type(parsed).fromisoformat(parsed.isoformat())
    if reparsed != parsed:
        raise AssertionError(
            "isoformat round-trip mismatch: %r -> %r" % (parsed, parsed.isoformat())
        )

    delta = timedelta(amount % 30, amount % 60, amount % 1000000)
    try:
        parsed + delta
        parsed - delta
    except (TypeError, OverflowError):
        pass
