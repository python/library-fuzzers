import io
import zoneinfo


def FuzzerRunOne(FuzzerInput):
    try:
        zoneinfo.ZoneInfo.from_file(io.BytesIO(FuzzerInput))
    except SystemError:
        raise
    except:
        return
