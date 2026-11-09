"""Fuzz marshal.loads() over untrusted bytes.

marshal is the deserialiser behind .pyc files and marshal.dumps()/loads();
unmarshalling attacker-supplied bytes must stay memory-safe: invalid type
tags, negative or oversized length fields, dangling ref tags and malformed
code objects are all attacker-controlled. Input is capped at 1 MiB; the
deserialisation itself is expected to reject malformed streams with
EOFError/ValueError/TypeError/RecursionError/MemoryError -- anything else
propagates and aborts the fuzzer as a finding.
"""
import marshal

MAX_MARSHAL_TEST_SIZE = 0x100000  # 1 MiB, matching the other size-capped targets


def FuzzerRunOne(FuzzerInput):
    if len(FuzzerInput) > MAX_MARSHAL_TEST_SIZE:
        return
    try:
        marshal.loads(FuzzerInput)
    except EOFError:
        pass
    except ValueError:
        pass
    except TypeError:
        pass
    except RecursionError:
        pass
    except MemoryError:
        pass
