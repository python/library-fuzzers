from fuzz_dp import FuzzedDataProvider
import unicodedata

NORMALIZE_FORMS = ['NFC', 'NFD', 'NFKC', 'NFKD']

MAX_CHARS = 5000       # cap on per-character iteration loops
MAX_STRING_SIZE = 10000  # cap on strings passed to normalize/lookup

OP_CATEGORY = 0
OP_BIDIRECTIONAL = 1
OP_NORMALIZE = 2
OP_NUMERIC = 3
OP_DECIMAL = 4
OP_COMBINING = 5
OP_EAST_ASIAN_WIDTH = 6
OP_MIRRORED = 7
OP_NAME = 8
OP_DECOMPOSITION = 9
OP_LOOKUP = 10
OP_DIGIT = 11
OP_IS_NORMALIZED = 12

# Fuzzes the unicodedata C module (Modules/unicodedata.c). Exercises
# character property lookups (category, bidirectional, combining,
# east_asian_width, mirrored), normalization (NFC/NFD/NFKC/NFKD and
# is_normalized), numeric/decimal/digit value extraction, character
# name/decomposition queries, and unicodedata.lookup() by name.
def FuzzerRunOne(FuzzerInput):
    if len(FuzzerInput) < 1 or len(FuzzerInput) > 0x10000:
        return
    fdp = FuzzedDataProvider(FuzzerInput)
    target = fdp.ConsumeIntInRange(OP_CATEGORY, OP_IS_NORMALIZED)
    try:
        if target == OP_CATEGORY:
            s = fdp.ConsumeUnicode(fdp.ConsumeIntInRange(1, MAX_CHARS))
            for ch in s:
                unicodedata.category(ch)
        elif target == OP_BIDIRECTIONAL:
            s = fdp.ConsumeUnicode(fdp.ConsumeIntInRange(1, MAX_CHARS))
            for ch in s:
                unicodedata.bidirectional(ch)
        elif target == OP_NORMALIZE:
            form = fdp.PickValueInList(NORMALIZE_FORMS)
            s = fdp.ConsumeUnicode(fdp.ConsumeIntInRange(1, MAX_STRING_SIZE))
            unicodedata.normalize(form, s)
        elif target == OP_NUMERIC:
            s = fdp.ConsumeUnicode(fdp.ConsumeIntInRange(1, MAX_CHARS))
            for ch in s:
                try:
                    unicodedata.numeric(ch)
                except ValueError:
                    pass
        elif target == OP_DECIMAL:
            s = fdp.ConsumeUnicode(fdp.ConsumeIntInRange(1, MAX_CHARS))
            for ch in s:
                try:
                    unicodedata.decimal(ch)
                except ValueError:
                    pass
        elif target == OP_COMBINING:
            s = fdp.ConsumeUnicode(fdp.ConsumeIntInRange(1, MAX_CHARS))
            for ch in s:
                unicodedata.combining(ch)
        elif target == OP_EAST_ASIAN_WIDTH:
            s = fdp.ConsumeUnicode(fdp.ConsumeIntInRange(1, MAX_CHARS))
            for ch in s:
                unicodedata.east_asian_width(ch)
        elif target == OP_MIRRORED:
            s = fdp.ConsumeUnicode(fdp.ConsumeIntInRange(1, MAX_CHARS))
            for ch in s:
                unicodedata.mirrored(ch)
        elif target == OP_NAME:
            s = fdp.ConsumeUnicode(fdp.ConsumeIntInRange(1, MAX_CHARS))
            for ch in s:
                try:
                    unicodedata.name(ch)
                except ValueError:
                    pass
        elif target == OP_DECOMPOSITION:
            s = fdp.ConsumeUnicode(fdp.ConsumeIntInRange(1, MAX_CHARS))
            for ch in s:
                unicodedata.decomposition(ch)
        elif target == OP_LOOKUP:
            s = fdp.ConsumeUnicode(fdp.ConsumeIntInRange(1, MAX_STRING_SIZE))
            try:
                unicodedata.lookup(s)
            except KeyError:
                pass
        elif target == OP_DIGIT:
            s = fdp.ConsumeUnicode(fdp.ConsumeIntInRange(1, MAX_CHARS))
            for ch in s:
                try:
                    unicodedata.digit(ch)
                except ValueError:
                    pass
        elif target == OP_IS_NORMALIZED:
            form = fdp.PickValueInList(NORMALIZE_FORMS)
            s = fdp.ConsumeUnicode(fdp.ConsumeIntInRange(1, MAX_STRING_SIZE))
            unicodedata.is_normalized(form, s)
    except Exception:
        pass
