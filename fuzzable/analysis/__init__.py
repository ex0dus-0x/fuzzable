import abc

# interesting patterns to parse for in unstripped symbols when determining fuzzability
INTERESTING_PATTERNS = ["Parse", "Read", "Buf", "File", "Input", "String", "Decode"]


class AnalysisBackend(abc.ABC):
    def __init__(self):
        pass
