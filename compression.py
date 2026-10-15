from fuzzeddataprovider import FuzzedDataProvider
import zlib
import bz2
import lzma

WBITS_CHOICES = [-15, 0, 15, 31, 47]
MAX_DECOMPRESS_LEN = 1024 * 1024  # 1 MiB cap to prevent OOM from small inputs

OP_ZLIB_DECOMPRESS = 0
OP_ZLIB_COMPRESS = 1
OP_ZLIB_CHECKSUM = 2
OP_BZ2_COMPRESS_DECOMPRESS = 3
OP_LZMA_DECOMPRESS = 4
OP_LZMA_COMPRESS = 5
NUM_OPS = 6


def op_zlib_decompress(fdp):
    wbits = fdp.PickValueInList(WBITS_CHOICES)
    use_zdict = fdp.ConsumeBool()
    do_flush = fdp.ConsumeBool()
    do_copy = fdp.ConsumeBool()
    zdict = b""
    if use_zdict:
        zdict_size = fdp.ConsumeIntInRange(1, 32768)
        zdict = fdp.ConsumeBytes(zdict_size)
    data = fdp.ConsumeBytes(fdp.remaining_bytes())
    kwargs = {}
    if zdict:
        kwargs["zdict"] = zdict
    dobj = zlib.decompressobj(wbits, **kwargs)
    dobj.decompress(data, MAX_DECOMPRESS_LEN)
    if do_flush:
        dobj.flush()
    if do_copy:
        copy_obj = dobj.copy()
        copy_obj.decompress(data, MAX_DECOMPRESS_LEN)


def op_zlib_compress(fdp):
    level = fdp.ConsumeIntInRange(0, 9)
    use_obj = fdp.ConsumeBool()
    do_copy = fdp.ConsumeBool()
    n = fdp.ConsumeIntInRange(1, 10000)
    data = fdp.ConsumeBytes(n)
    if not data:
        return
    if use_obj:
        cobj = zlib.compressobj(level)
        cobj.compress(data)
        if do_copy:
            copy_obj = cobj.copy()
            copy_obj.flush()
        cobj.flush()
    else:
        zlib.compress(data, level)


def op_zlib_checksum(fdp):
    use_crc = fdp.ConsumeBool()
    data = fdp.ConsumeBytes(fdp.remaining_bytes())
    if use_crc:
        zlib.crc32(data)
    else:
        zlib.adler32(data)


def op_bz2(fdp):
    do_compress = fdp.ConsumeBool()
    n = (
        fdp.ConsumeIntInRange(1, min(fdp.remaining_bytes(), 10000))
        if fdp.remaining_bytes() > 0
        else 0
    )
    if n == 0:
        return
    data = fdp.ConsumeBytes(n)
    if do_compress:
        bz2.compress(data)
    else:
        dobj = bz2.BZ2Decompressor()
        dobj.decompress(data, MAX_DECOMPRESS_LEN)


def op_lzma_decompress(fdp):
    formats = [lzma.FORMAT_AUTO, lzma.FORMAT_XZ, lzma.FORMAT_ALONE, lzma.FORMAT_RAW]
    fmt = fdp.PickValueInList(formats)
    n = (
        fdp.ConsumeIntInRange(1, min(fdp.remaining_bytes(), 10000))
        if fdp.remaining_bytes() > 0
        else 0
    )
    if n == 0:
        return
    data = fdp.ConsumeBytes(n)
    kwargs = {"format": fmt, "memlimit": 16 * 1024 * 1024}
    if fmt == lzma.FORMAT_RAW:
        kwargs["filters"] = [{"id": lzma.FILTER_LZMA2}]
        del kwargs["memlimit"]
    dobj = lzma.LZMADecompressor(**kwargs)
    dobj.decompress(data, MAX_DECOMPRESS_LEN)


def op_lzma_compress(fdp):
    n = (
        fdp.ConsumeIntInRange(1, min(fdp.remaining_bytes(), 10000))
        if fdp.remaining_bytes() > 0
        else 0
    )
    if n == 0:
        return
    data = fdp.ConsumeBytes(n)
    lzma.compress(data)


# Fuzzes zlib, bz2, and lzma C modules (Modules/zlibmodule.c,
# Modules/_bz2module.c, Modules/_lzmamodule.c). Exercises decompression
# with various wbits/format settings and optional zlib dictionaries,
# compression at different levels with compressobj/compress, CRC32/Adler32
# checksums, and BZ2/LZMA decompressor objects with memory limits.
def FuzzerRunOne(FuzzerInput):
    if len(FuzzerInput) < 1 or len(FuzzerInput) > 0x100000:
        return
    fdp = FuzzedDataProvider(FuzzerInput)
    op = fdp.ConsumeIntInRange(0, NUM_OPS - 1)
    try:
        if op == OP_ZLIB_DECOMPRESS:
            op_zlib_decompress(fdp)
        elif op == OP_ZLIB_COMPRESS:
            op_zlib_compress(fdp)
        elif op == OP_ZLIB_CHECKSUM:
            op_zlib_checksum(fdp)
        elif op == OP_BZ2_COMPRESS_DECOMPRESS:
            op_bz2(fdp)
        elif op == OP_LZMA_DECOMPRESS:
            op_lzma_decompress(fdp)
        else:
            op_lzma_compress(fdp)
    except Exception:
        pass
