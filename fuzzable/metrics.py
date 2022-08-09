"""
metrics.py

    Dataclass definitions for various metrics collected during qthe risk analysis.
"""
import json
import functools
import typing as t

from dataclasses import dataclass, field, asdict


@dataclass
class CoverageReport:
    """TODO"""

    bb_depth: int
    function_depth: int
    ins_depth: int


@dataclass
class CallScore:
    """Assigned fuzzability score for an individual function target."""

    name: str
    loc: str

    # does not attribute to rank, but helps with determining what to filter
    toplevel: bool

    # does not attribute to rank, but helps with binary analysis
    stripped: t.Optional[bool]

    # quantifies the number of fuzzer friendly words that exist in the target's name
    fuzz_friendly: int

    # quantifies the number of fuzzer arguments that flow into
    risky_sinks: int

    # quantifies the number of natural loops in the BB graph
    natural_loops: int

    # quantifies complexity based on edges and nodes present
    cyclomatic_complexity: int

    # represents coverage by different granularities
    # coverage_depth: CoverageReport
    coverage_depth: int

    # mutable values that are to be set after analysis
    _final_rank: int = field(init=False, repr=False)
    _final_score: float = field(init=False, repr=False)

    """
    Getters and setters for calculated rank and score
    """

    @property
    def rank(self) -> int:
        """Rank of an individual function in a list of parsed functions"""
        return self._final_rank

    @rank.setter
    def rank(self, to_set: int) -> None:
        """Call to set the rank after analysis and ranking"""
        self._final_rank = float(to_set)

    @property
    def score(self) -> float:
        """Final calculated fuzzability score based on metrics"""
        return self._final_score

    @score.setter
    def score(self, to_set: float) -> None:
        """Call to set the fuzzability score after analysis and calculation"""
        self._final_score = float(to_set)

    """
    Overloaded operators for sorting
    """

    def __eq__(self, other):
        self._final_rank == other._final_rank

    def __lt__(self, other):
        self._final_rank < other._final_rank

    def __gt__(self, other):
        self._final_rank > other._final_rank

    """
    Properties to export score into flat structures
    """

    def asdict(self) -> t.Dict[str, t.Any]:
        return asdict(self)

    @property
    def matrix_row(self) -> t.List[int]:
        """Transforms attributes into a list of integers for a matrix"""
        return [
            self.fuzz_friendly,
            self.risky_sinks,
            self.natural_loops,
            self.coverage_depth,
            self.cyclomatic_complexity,
        ]

    @property
    def binja_markdown_row(self) -> str:
        """Output as a markdown/ascii table row when displaying back to user"""
        return f"| [{self.name}](binaryninja://?expr={self.name}) | {self.loc} | {self.score} | {self.fuzz_friendly} | {self.risky_sinks} | {self.natural_loops} | {self.cyclomatic_complexity} | {self.coverage_depth} | \n"

    @property
    def csv_row(self) -> str:
        """Generate a CSV row for exporting to file"""
        return f"{self.name}, {self.loc}, {self.stripped}, {self.fuzz_friendly}, {self.risky_sinks}, {self.natural_loops}, {self.cyclomatic_complexity}, {self.coverage_depth}, {self.score}\n"

    @functools.cached_property
    def simple_fuzzability(self) -> int:
        """Simple fuzzability"""
        self._final_score = sum(self.matrix_row)
        return self._final_score
