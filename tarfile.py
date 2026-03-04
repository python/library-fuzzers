import io
import tarfile

import sys
import shutil
import pathlib
import tempfile
import typing


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
    has_file = False
    try:
        with tarfile.open(fileobj=io.BytesIO(FuzzerInput), ignore_zeros=True, errorlevel=0) as tf:
            for tarinfo in tf:
                tarinfo.name
                tarinfo.size
                tarinfo.mtime
                tarinfo.mode
                tarinfo.type
                tarinfo.uid
                tarinfo.gid
                tarinfo.uname
                tarinfo.gname

                if tarinfo.type in (tarfile.REGTYPE, tarfile.AREGTYPE):
                    has_file = True
    except tarfile.TarError:
        return
    except UnicodeDecodeError:
        return
    except EOFError:
        return

    # Assert that all files created by tar are
    # relative to the extraction directory.
    with tempfile.TemporaryDirectory() as tmp_dir, OpenFileRecorder() as record:
        try:
            with tarfile.open(fileobj=io.BytesIO(FuzzerInput), ignore_zeros=True, errorlevel=0) as tf:
                tf.extractall(path=tmp_dir, filter="data")
        finally:
            opened_paths = record.paths
            shutil.rmtree(tmp_dir)

    # Assert that every opened file is a subdirectory
    # of the extraction directory.
    assert has_file == bool(opened_paths), "Recorded paths was empty, despite files in archive"
    for filepath in opened_paths:
        assert pathlib.Path(filepath).is_relative_to(tmp_dir), f"{filepath} is not relative to {tmp_dir}"
