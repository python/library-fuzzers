from encodings.aliases import aliases

ALL_CODECS = sorted(set(aliases.values()))

def FuzzerRunOne(FuzzerInput):
    if len(FuzzerInput) < 2:
        return
    if FuzzerInput[0] & 1:
        codec = ALL_CODECS[FuzzerInput[1] % len(ALL_CODECS)]
        data = FuzzerInput[2:]
    else:
        l = len(FuzzerInput) // 2
        codec = FuzzerInput[l:].decode("utf-8", "replace").strip()
        data = FuzzerInput[:l]
    try:
        data.decode(codec)
    except SystemError:
        raise
    except Exception:
        pass
