import plistlib
import xml.parsers.expat


def FuzzerRunOne(FuzzerInput):
    try:
        data = plistlib.loads(FuzzerInput)
    except plistlib.InvalidFileException:
        return
    except xml.parsers.expat.ExpatError:
        return
    except ValueError:
        return
    except LookupError:
        # XML input can declare an unknown encoding.
        return
    try:
        plistlib.dumps(data, skipkeys=True, fmt=plistlib.FMT_XML)
        plistlib.dumps(data, skipkeys=True, fmt=plistlib.FMT_BINARY)
    except TypeError:
        return
    except OverflowError:
        return
