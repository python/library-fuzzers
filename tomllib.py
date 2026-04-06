import tomllib

POSSIBLE_EXCEPTIONS = (
    KeyError,
    RecursionError,
    tomllib.TOMLDecodeError,
    TypeError,
    ValueError,
)


def FuzzerRunOne(FuzzerInput):
    try:
        tomllib.loads(FuzzerInput.decode("utf-8", "replace"))
    except POSSIBLE_EXCEPTIONS:
        return
