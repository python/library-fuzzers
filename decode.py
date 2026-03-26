from encodings.aliases import aliases

ALL_CODECS = sorted(set(aliases.values()))

def FuzzerRunOne(FuzzerInput):
    if len(FuzzerInput) < 2:
        return
    codec = ALL_CODECS[FuzzerInput[0] % len(ALL_CODECS)]
    data = FuzzerInput[1:]
    try:
        data.decode(codec)
    except SystemError:
        raise
    except Exception:
        pass
