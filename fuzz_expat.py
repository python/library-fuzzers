from fuzz_dp import FuzzedDataProvider
from xml.parsers import expat
import io

ENCODINGS = [None, 'utf-8', 'iso-8859-1']

# Fuzzes the expat XML parser (Modules/expat/xmlparse.c, Modules/pyexpat.c).
# Creates a parser with a fuzzed encoding selection (None, UTF-8,
# ISO-8859-1), installs handlers for elements, character data, PIs,
# comments, and CDATA sections, then parses fuzzed bytes via Parse()
# or ParseFile().
def FuzzerRunOne(FuzzerInput):
    if len(FuzzerInput) < 1 or len(FuzzerInput) > 0x10000:
        return
    fdp = FuzzedDataProvider(FuzzerInput)
    use_parse_file = fdp.ConsumeBool()
    encoding = fdp.PickValueInList(ENCODINGS)
    try:
        p = expat.ParserCreate(encoding)
        p.StartElementHandler = lambda name, attrs: None
        p.EndElementHandler = lambda name: None
        p.CharacterDataHandler = lambda data: None
        p.ProcessingInstructionHandler = lambda target, data: None
        p.CommentHandler = lambda data: None
        p.StartCdataSectionHandler = lambda: None
        p.EndCdataSectionHandler = lambda: None
        p.DefaultHandler = lambda data: None

        data = fdp.ConsumeBytes(fdp.remaining_bytes())
        if use_parse_file:
            p.ParseFile(io.BytesIO(data))
        else:
            p.Parse(data, True)
    except expat.ExpatError:
        pass
    except Exception:
        pass
