import io
import sys
import shutil
import pathlib
import tempfile
import typing
import zlib

import zipfile


class OpenFileRecorder:
    """Record files which are opened using sys.audit()"""

    _record_open_files: typing.ClassVar[bool] = False
    _recorded_files: typing.ClassVar[set[pathlib.Path]] = set()

    @staticmethod
    def _sys_audit_record_open(event, args):
        if event == "open" and OpenFileRecorder._record_open_files:
            OpenFileRecorder._recorded_files.add(pathlib.Path(args[0]))

    @property
    def paths(self) -> set[pathlib.Path]:
        return OpenFileRecorder._recorded_files.copy()

    def __enter__(self):
        if OpenFileRecorder._record_open_files:
            raise RuntimeError("OpenFileRecorder already recording")
        OpenFileRecorder._record_open_files = True
        OpenFileRecorder._recorded_files.clear()
        return self

    def __exit__(self, *_):
        OpenFileRecorder._recorded_files.clear()
        OpenFileRecorder._record_open_files = False


sys.addaudithook(OpenFileRecorder._sys_audit_record_open)


def FuzzerRunOne(FuzzerInput):
    try:
        with zipfile.ZipFile(io.BytesIO(FuzzerInput), strict_timestamps=False) as zf:
            for info in zf.infolist():
                info.filename
                info.date_time
                info.compress_type
                info.comment
                info.extra
                info.create_system
                info.create_version
                info.extract_version
                info.reserved
                info.flag_bits
                info.volume
                info.internal_attr
                info.external_attr
                info.header_offset
                info.CRC
                info.compress_size
                info.file_size
    except zipfile.BadZipFile:
        return
    # zipfile raises 'NotImplementedError' for
    # ZIP versions that aren't supported.
    except NotImplementedError as e:
        if "zip file version" in str(e):
            return
        raise
    except UnicodeDecodeError:
        return

    # Assert that all files created by ZIP are
    # relative to the extraction directory.
    with tempfile.TemporaryDirectory() as tmp_dir, OpenFileRecorder() as record:
        try:
            with zipfile.ZipFile(io.BytesIO(FuzzerInput)) as zf:
                zf.extractall(path=tmp_dir)
        except (
            zipfile.BadZipFile,
            zlib.error,
            NotImplementedError,
            UnicodeDecodeError,
            UnicodeEncodeError,
            RuntimeError,
            ValueError,
            EOFError,
            OverflowError,
        ):
            return
        except OSError as e:
            if "Invalid data stream" in str(e):
                return
            elif "File name too long" in str(e):
                return
            raise
        finally:
            shutil.rmtree(tmp_dir)

    # Assert that every opened file is a subdirectory
    # of the extraction directory.
    for filepath in record.paths:
        assert pathlib.Path(filepath).is_relative_to(tmp_dir), (
            f"{filepath} is not relative to {tmp_dir}"
        )
