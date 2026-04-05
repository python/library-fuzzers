import tomllib

def FuzzerRunOne(FuzzerInput):
    try:
        tomllib.loads(FuzzerInput.decode("utf-8", "replace"))
    except KeyError:
        return
    except RecursionError:
        return
    except tomllib.TOMLDecodeError:
        return
    except TypeError:
        return
    except ValueError:
        return

