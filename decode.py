def FuzzerRunOne(FuzzerInput):
    half = int(len(FuzzerInput) / 2)
    A = FuzzerInput[:half]
    B = FuzzerInput[half:].decode("utf-8", "replace").strip()
    try:
        A.decode(B)
    except SystemError:
        raise
    except:
        pass
