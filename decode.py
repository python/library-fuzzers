import encodings
import pkgutil

ALL_CODECS = sorted(
    name
    for _, name, _ in pkgutil.iter_modules(encodings.__path__)
    if not name.startswith("_") and name != "aliases"
)


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
