import abc
import functools

from dataclasses import dataclass

# interesting patterns to parse for in unstripped symbols when determining fuzzability
INTERESTING_PATTERNS = ["Parse", "Read", "Buf", "File", "Input", "String", "Decode"]


class AnalysisBackend(abc.ABC):
    @abc.abstractmethod
    def __init__(self):
        pass

    @abc.abstractmethod
    def run(self) -> None:
        pass

    @abc.abstractmethod
    @staticmethod
    def ignore(self, symbol) -> bool:
        """
        Helper to determine if a parsed symbol should be skipped
        for analysis based on the object for the given analysis backend.
        """
        pass

    @abc.abstractmethod
    @functools.cached_property
    def fuzzability(self) -> float:
        pass

    def markdown_row(self):
        """Output as a Markdown row when displaying back to user"""
        return f"| [{self.name}](binaryninja://?expr={self.name}) | {self.fuzzability} | {self.depth} | {self.has_loop} | {self.recursive} | \n"

    def csv_row(self):
        """Generate a CSV row for exporting to file"""
        return f"{self.name}, {self.stripped}, {self.interesting_name}, {self.interesting_args}, {self.depth}, {self.has_loop}, {self.fuzzability}\n"


@dataclass
class CandidateFuzzabililty:
    pass