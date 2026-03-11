import difflib

def FuzzerRunOne(FuzzerInput):
    # SequenceMatcher is quadratic time worst case (see Lib/difflib.py).
    # Cap input size to avoid timeouts on large inputs.
    if not (0 < len(FuzzerInput) < 4096):
        return
    l = int(len(FuzzerInput)/2)
    A = FuzzerInput[:l].decode("utf-8", "replace").splitlines()
    B = FuzzerInput[l:].decode("utf-8", "replace").splitlines()
    for x in difflib.unified_diff(A, B):
        pass
    for x in difflib.context_diff(A, B):
        pass
    difflib.HtmlDiff().make_file(A, B)


