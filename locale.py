from fuzzeddataprovider import FuzzedDataProvider
import locale

OP_STRXFRM = 0
OP_STRCOLL = 1


# Fuzzes the _locale C module (Modules/_localemodule.c).
# Exercises locale.strxfrm() for locale-aware string transformation
# and locale.strcoll() for locale-aware string comparison, both with
# fuzz-generated Unicode input.
def FuzzerRunOne(FuzzerInput):
    if len(FuzzerInput) < 1 or len(FuzzerInput) > 0x10000:
        return
    fdp = FuzzedDataProvider(FuzzerInput)
    target = fdp.ConsumeIntInRange(OP_STRXFRM, OP_STRCOLL)
    n = (
        fdp.ConsumeIntInRange(1, min(fdp.remaining_bytes(), 10000))
        if fdp.remaining_bytes() > 0
        else 0
    )
    if n == 0:
        return
    s = fdp.ConsumeUnicode(n)
    try:
        if target == OP_STRXFRM:
            locale.strxfrm(s)
        elif target == OP_STRCOLL:
            n2 = (
                fdp.ConsumeIntInRange(1, min(fdp.remaining_bytes(), 10000))
                if fdp.remaining_bytes() > 0
                else 0
            )
            s2 = fdp.ConsumeUnicode(n2) if n2 > 0 else ""
            locale.strcoll(s, s2)
    except Exception:
        pass
