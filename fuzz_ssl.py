from fuzz_dp import FuzzedDataProvider
import os
import ssl
import tempfile

DER_TO_PEM_CERT = 0
LOAD_VERIFY_LOCATIONS = 1

# Fuzzes the _ssl C module (Modules/_ssl.c). Exercises DER-to-PEM
# certificate conversion via ssl.DER_cert_to_PEM_cert(), and
# SSLContext certificate loading via load_verify_locations() with
# fuzzed PEM data written to a temporary file.
def FuzzerRunOne(FuzzerInput):
    if len(FuzzerInput) < 1 or len(FuzzerInput) > 0x100000:
        return
    fdp = FuzzedDataProvider(FuzzerInput)
    target = fdp.ConsumeIntInRange(DER_TO_PEM_CERT, LOAD_VERIFY_LOCATIONS)
    data = fdp.ConsumeBytes(fdp.remaining_bytes())
    try:
        if target == DER_TO_PEM_CERT:
            ssl.DER_cert_to_PEM_cert(data)
        elif target == LOAD_VERIFY_LOCATIONS:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            with tempfile.NamedTemporaryFile(suffix='.pem', delete=False) as tmp:
                tmpname = tmp.name
                tmp.write(data)
                tmp.flush()
            try:
                ctx.load_verify_locations(tmpname)
            finally:
                os.unlink(tmpname)
    except Exception:
        pass
