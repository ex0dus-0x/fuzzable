import abc

# interesting patterns to parse for in unstripped symbols when determining fuzzability
INTERESTING_PATTERNS = ["Parse", "Read", "Buf", "File", "Input", "String", "Decode"]


class AnalysisBackend(abc.ABC):

    @abc.abstractmethod
    def __init__(self):
        pass

    @abc.abstractmethod
    def run_with_conf(self):
        pass