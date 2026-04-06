import io
import tarfile

from hypothesis import given, settings
from hypothesis import strategies as st


def utf8_text(*, max_size: int, min_size: int = 0) -> st.SearchStrategy[str]:
    """Returns UTF-8 text that, when encoded to bytes,
    is within the size restrictions.
    """
    return st.text(min_size=min_size, max_size=max_size).filter(
        lambda s: min_size <= len(s.encode("utf-8")) <= max_size
    )


def tar_integers(
    *, format: int, digits: int = 1, allow_negative: bool = False
) -> st.SearchStrategy[tuple[io.BytesIO, tarfile.TarFile]]:
    """tar has a unique way of encoding integers that is format-dependent
    and based on the number of "digits" allowed for a value.
    """
    if digits <= 0:
        raise ValueError("Digits must be greater than one.")
    if format == tarfile.GNU_FORMAT:
        min_value = -(256 ** (digits - 1)) if allow_negative else 0
        max_value = (256 ** (digits - 1)) - 1
    else:
        min_value = 0
        max_value = (4**digits) - 1
    return st.integers(min_value=min_value, max_value=max_value)


@st.composite
@settings(print_blob=True)
def tar_archives(draw):
    buf = io.BytesIO()
    format = draw(
        st.sampled_from((tarfile.GNU_FORMAT, tarfile.PAX_FORMAT, tarfile.USTAR_FORMAT))
    )
    tar = tarfile.TarFile(fileobj=buf, format=format, mode="w")
    types = list(tarfile.REGULAR_TYPES)

    for _ in range(draw(st.integers(min_value=1, max_value=10))):
        info = tarfile.TarInfo(
            name=draw(utf8_text(min_size=1, max_size=tarfile.LENGTH_NAME))
        )
        if draw(st.booleans()):
            fileobj = io.BytesIO(draw(st.binary(min_size=0, max_size=0xFFFF)))
        else:
            fileobj = None

        info.type = draw(st.sampled_from(types))
        info.mode = draw(tar_integers(format=format, digits=8))
        info.uid = draw(tar_integers(format=format, digits=8))
        info.gid = draw(tar_integers(format=format, digits=8))
        info.mtime = draw(tar_integers(format=format, digits=12))
        info.devmajor = draw(tar_integers(format=format, digits=8))
        info.devminor = draw(tar_integers(format=format, digits=8))

        if draw(st.booleans()):
            info.linkname = draw(utf8_text(min_size=1, max_size=tarfile.LENGTH_LINK))

        def maybe_set_pax_header(obj, name, value):
            if draw(st.booleans()):
                obj.pax_headers[name] = value

        if format == tarfile.PAX_FORMAT:
            maybe_set_pax_header(info, "uname", draw(st.text(max_size=32)))
            maybe_set_pax_header(info, "gname", draw(st.text(max_size=32)))
            maybe_set_pax_header(
                info,
                "path",
                draw(utf8_text(min_size=1, max_size=tarfile.LENGTH_NAME)),
            )
            maybe_set_pax_header(
                info,
                "linkpath",
                draw(utf8_text(min_size=1, max_size=tarfile.LENGTH_LINK)),
            )

        tar.addfile(info, fileobj=fileobj)

    return buf, tar


@given(tar_archives())
@settings(print_blob=True)
def tar_archive_fuzz_target(buf_tar: tuple[io.BytesIO, tarfile.TarFile]) -> None:
    buf, tar1 = buf_tar
    tar2 = tarfile.TarFile(fileobj=buf)
    # Assert that tar files round-trip.
    assert list(tar1.getmembers()) == list(tar2.getmembers()), repr(buf.getvalue())


# Exposes the Hypothesis fuzz target for integrating with OSS-Fuzz.
FuzzerRunOne = tar_archive_fuzz_target.hypothesis.fuzz_one_input

# Pre-compute Hypothesis's Unicode charmap at module load time to avoid
# timeouts.
# See https://github.com/HypothesisWorks/hypothesis/issues/1153
st.text().example()
