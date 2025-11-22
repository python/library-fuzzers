import xml.etree.ElementTree as ET

def FuzzerRunOne(FuzzerInput):
    try:
        tree = ET.fromstring(FuzzerInput.decode("utf-8", "replace"))
    except:
        pass
