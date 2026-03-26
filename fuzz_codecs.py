from fuzz_dp import FuzzedDataProvider
import codecs
import io

DECODERS = [
    "utf-7", "shift_jis", "euc-jp", "gb2312", "big5", "iso-2022-jp",
    "euc-kr", "gb18030", "big5hkscs", "charmap", "ascii", "latin-1",
    "cp1252", "unicode_escape", "raw_unicode_escape", "utf-16", "utf-32",
]

ENCODERS = [
    "shift_jis", "euc-jp", "gb2312", "big5", "iso-2022-jp", "euc-kr",
    "gb18030", "big5hkscs", "unicode_escape", "raw_unicode_escape",
    "utf-7", "utf-8", "utf-16", "utf-16-le", "utf-16-be", "utf-32",
    "latin-1", "ascii", "charmap",
]

INC_DEC_CODECS = ["shift_jis", "gb18030", "utf-16"]
INC_ENC_CODECS = ["shift_jis", "utf-8"]

OP_DECODE = 0
OP_ENCODE = 1
OP_INCREMENTAL_DECODE = 2
OP_INCREMENTAL_ENCODE = 3
OP_STREAM_READ = 4

def op_decode(fdp):
    codec = fdp.PickValueInList(DECODERS)
    data = fdp.ConsumeBytes(fdp.remaining_bytes())
    codecs.decode(data, codec, 'replace')

def op_encode(fdp):
    codec = fdp.PickValueInList(ENCODERS)
    n = fdp.ConsumeIntInRange(1, min(fdp.remaining_bytes(), 10000)) if fdp.remaining_bytes() > 0 else 0
    if n == 0:
        return
    s = fdp.ConsumeUnicode(n)
    codecs.encode(s, codec, 'replace')

def op_incremental_decode(fdp):
    codec = fdp.PickValueInList(INC_DEC_CODECS)
    chunk1_size = fdp.ConsumeIntInRange(0, 10000)
    chunk1 = fdp.ConsumeBytes(chunk1_size)
    chunk2 = fdp.ConsumeBytes(fdp.remaining_bytes())
    decoder = codecs.getincrementaldecoder(codec)('replace')
    decoder.decode(chunk1)
    decoder.decode(chunk2, True)
    decoder.getstate()
    decoder.reset()

def op_incremental_encode(fdp):
    codec = fdp.PickValueInList(INC_ENC_CODECS)
    n = fdp.ConsumeIntInRange(1, min(fdp.remaining_bytes(), 10000)) if fdp.remaining_bytes() > 0 else 0
    if n == 0:
        return
    s = fdp.ConsumeUnicode(n)
    split = fdp.ConsumeIntInRange(0, len(s))
    encoder = codecs.getincrementalencoder(codec)('replace')
    encoder.encode(s[:split])
    encoder.reset()
    encoder.encode(s[split:])
    encoder.getstate()

def op_stream(fdp):
    data = fdp.ConsumeBytes(fdp.remaining_bytes())
    bio = io.BytesIO(data)
    reader = codecs.getreader('utf-8')(bio, 'replace')
    reader.read()

# Fuzzes CPython's codec infrastructure (Modules/cjkcodecs/, Python/codecs.c).
# Exercises full and incremental encode/decode for CJK codecs (Shift-JIS,
# EUC-JP, GB2312, Big5, ISO-2022-JP, EUC-KR, GB18030, Big5-HKSCS) and
# Western/Unicode codecs (UTF-7/16/32, charmap, unicode_escape, latin-1).
# Also tests stream-based reading via codecs.getreader().
def FuzzerRunOne(FuzzerInput):
    if len(FuzzerInput) < 1 or len(FuzzerInput) > 0x100000:
        return
    fdp = FuzzedDataProvider(FuzzerInput)
    op = fdp.ConsumeIntInRange(OP_DECODE, OP_STREAM_READ)
    try:
        if op == OP_DECODE:
            op_decode(fdp)
        elif op == OP_ENCODE:
            op_encode(fdp)
        elif op == OP_INCREMENTAL_DECODE:
            op_incremental_decode(fdp)
        elif op == OP_INCREMENTAL_ENCODE:
            op_incremental_encode(fdp)
        else:
            op_stream(fdp)
    except Exception:
        pass
