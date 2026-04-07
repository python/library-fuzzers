from email.parser import Parser
from email.policy import HTTP


def FuzzerRunOne(FuzzerInput):
    try:
        Parser(policy=HTTP).parsestr(FuzzerInput.decode("utf-8", "replace"))
    except SystemError:
        raise
    except:
        pass
