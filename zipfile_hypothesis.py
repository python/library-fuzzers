import datetime
import io
import zipfile
import math

from hypothesis import given
from hypothesis import strategies as st

ZIP_EPOCH_START = datetime.datetime(1980, 1, 1)
ZIP_EPOCH_END = datetime.datetime(2107, 12, 31, 23, 59, 59)
ZIP_EPOCH_LENGTH = int(math.ceil((ZIP_EPOCH_END - ZIP_EPOCH_START).total_seconds()))


def utf8_text(*, max_size: int, min_size: int = 0) -> st.SearchStrategy[str]:
    """Returns UTF-8 text that, when encoded to bytes,
    is within the size restrictions.
    """
    return st.text(min_size=min_size, max_size=max_size).filter(
        lambda s: min_size <= len(s.encode("utf-8")) <= max_size
    )


def zip_date_time() -> st.SearchStrategy[tuple[int, int, int, int, int, int, int]]:
    """Returns a tuple of (year, month, day, hour, minute, second)
    for valid values within a ZIP archive.
    """
    return st.integers(min_value=0, max_value=ZIP_EPOCH_LENGTH).map(
        lambda s: (ZIP_EPOCH_START + datetime.timedelta(seconds=s)).timetuple()[:6]
    )


@st.composite
def zip_archives(draw):
    compression_types = [
        zipfile.ZIP_STORED,
        zipfile.ZIP_DEFLATED,
        zipfile.ZIP_BZIP2,
        zipfile.ZIP_LZMA,
    ]
    try:
        import compression.zstd

        compression_types.append(zipfile.ZIP_ZSTANDARD)
    except ImportError:
        pass

    buf = io.BytesIO()
    zfp = zipfile.ZipFile(buf, "w")

    for _ in range(draw(st.integers(min_value=0, max_value=10))):
        zpi = zipfile.ZipInfo()
        zpi.filename = draw(utf8_text(min_size=1, max_size=0xFFFF))
        zpi.date_time = draw(zip_date_time())

        if draw(st.booleans()):
            zpi.flag_bits |= zipfile._MASK_USE_DATA_DESCRIPTOR

        zpi.compress_type = draw(st.sampled_from(compression_types))
        zpi._compresslevel = draw(st.integers(min_value=1, max_value=9))
        zpi.comment = draw(st.binary(min_size=0, max_size=0xFFFF))

        force_zip64 = draw(st.booleans())
        with zfp.open(zpi, mode="w", force_zip64=force_zip64) as f:
            f.write(b"")

    zfp.close()
    return buf, zfp


def zipinfo_dict(zi):
    return {k: getattr(zip, k, None) for k in zi.__slots__}



@given(zip_archives())
def zip_archive_fuzz_target(buf_zfp: tuple[io.BytesIO, zipfile.ZipFile]) -> None:
    buf, zfp1 = buf_zfp
    zi1 = [zipinfo_dict(zi) for zi in zfp1.infolist()]
    with zipfile.ZipFile(buf, "r") as zfp2:
        zi2 = [zipinfo_dict(zi) for zi in zfp2.infolist()]
    # Assert that ZIP files round-trip.
    assert (zi1 == zi2), f"{zi1!r} != {zi2!r}" 


# Exposes the Hypothesis fuzz target for integrating with OSS-Fuzz.
FuzzerRunOne = zip_archive_fuzz_target.hypothesis.fuzz_one_input
