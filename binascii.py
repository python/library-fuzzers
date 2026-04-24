from fuzzeddataprovider import FuzzedDataProvider
import binascii

# Top-level operation constants for FuzzerRunOne
OP_DECODE = 0
OP_ENCODE = 1
OP_CHECKSUM = 2
OP_ROUNDTRIP = 3

# Decode/encode sub-operation constants
CODEC_BASE64_STRICT = 0
CODEC_HEX = 1
CODEC_UU = 2
CODEC_QP = 3
CODEC_BASE64 = 4
CODEC_BASE64_ALT = 5


def op_decode(fdp):
    which = fdp.ConsumeIntInRange(CODEC_BASE64_STRICT, CODEC_BASE64_ALT)
    strict = fdp.ConsumeBool()
    data = fdp.ConsumeBytes(fdp.remaining_bytes())
    if which == CODEC_BASE64_STRICT:
        if strict:
            binascii.a2b_base64(data, strict_mode=True)
        else:
            binascii.a2b_base64(data)
    elif which == CODEC_HEX:
        binascii.a2b_hex(data)
    elif which == CODEC_UU:
        binascii.a2b_uu(data)
    elif which == CODEC_QP:
        binascii.a2b_qp(data)
    elif which == CODEC_BASE64:
        binascii.a2b_base64(data)
    elif which == CODEC_BASE64_ALT:
        binascii.a2b_base64(data)


def op_encode(fdp):
    which = fdp.ConsumeIntInRange(CODEC_BASE64_STRICT, CODEC_BASE64_ALT)
    newline = fdp.ConsumeBool()
    data = fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 10000))
    if not data:
        return
    if which == CODEC_BASE64_STRICT:
        binascii.b2a_base64(data, newline=newline)
    elif which == CODEC_HEX:
        binascii.b2a_hex(data)
    elif which == CODEC_UU:
        uu_data = fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 45))
        binascii.b2a_uu(uu_data)
    elif which == CODEC_QP:
        binascii.b2a_qp(data)
    elif which == CODEC_BASE64:
        binascii.b2a_base64(data)
    elif which == CODEC_BASE64_ALT:
        binascii.b2a_base64(data)


def op_checksum(fdp):
    use_crc32 = fdp.ConsumeBool()
    data = fdp.ConsumeBytes(fdp.remaining_bytes())
    if use_crc32:
        binascii.crc32(data)
    else:
        binascii.crc_hqx(data, 0)


def op_roundtrip(fdp):
    data = fdp.ConsumeBytes(fdp.remaining_bytes())
    hexed = binascii.hexlify(data)
    binascii.unhexlify(hexed)


# Fuzzes the binascii module's C implementation (Modules/binascii.c).
# Exercises binary-to-ASCII and ASCII-to-binary conversions for base64,
# hex, UU-encoding, and quoted-printable codecs. Also tests CRC32,
# CRC-HQX checksums, and hexlify/unhexlify roundtrips.
def FuzzerRunOne(FuzzerInput):
    if len(FuzzerInput) < 1 or len(FuzzerInput) > 0x100000:
        return
    fdp = FuzzedDataProvider(FuzzerInput)
    op = fdp.ConsumeIntInRange(OP_DECODE, OP_ROUNDTRIP)
    try:
        if op == OP_DECODE:
            op_decode(fdp)
        elif op == OP_ENCODE:
            op_encode(fdp)
        elif op == OP_CHECKSUM:
            op_checksum(fdp)
        else:
            op_roundtrip(fdp)
    except Exception:
        pass
