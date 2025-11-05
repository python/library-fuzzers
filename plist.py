import plistlib
import xml.parsers.expat

def FuzzerRunOne(FuzzerInput):
    try:
        data = plistlib.loads(FuzzerInput)
    except plistlib.InvalidFileException:
        return
    except xml.parsers.expat.ExpatError:
        return
    try:
        plistlib.dumps(data, skipkeys=True, fmt=plistlib.FMT_XML)
        plistlib.dumps(data, skipkeys=True, fmt=plistlib.FMT_BINARY)
    except TypeError:
        return
    except OverflowError:
        return

