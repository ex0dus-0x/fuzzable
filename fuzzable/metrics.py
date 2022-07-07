"""
metrics.py
"""
import functools
import typing as t

from dataclasses import dataclass

@dataclass
class CoverageReport:
    """
    At a given function symbol, calculate the coverage depth at
    """

    bb_depth: int
    function_depth: int
    ins_depth: int


@dataclass
class CallScore:
    """Assigned fuzzability score for an individual function target."""

    name: str

    toplevel: bool

    fuzz_friendly: bool
    has_risky_sink: bool
    contains_loop: bool
    coverage_depth: CoverageReport

    # binary-only, optional
    stripped: t.Optional[bool]

    @property
    def table_row(self) -> str:
        """Output as a Markdown row when displaying back to user"""
        return f"| [{self.name}](binaryninja://?expr={self.name}) | {self.fuzzability} | {self.depth} | {self.has_loop} | {self.recursive} | \n"

    @property
    def csv_row(self) -> str:
        """Generate a CSV row for exporting to file"""
        return f"{self.name}, {self.stripped}, {self.interesting_name}, {self.interesting_args}, {self.depth}, {self.has_loop}, {self.fuzzability}\n"

    @functools.cached_property
    def fuzzability(self) -> float:
        """
        Calculate a cached fuzzability score for the given function target
        based on the analysis metrics.
        """

        score = 0.0

        # function is publicly exposed
        if not self.stripped:
            score += 1.0

            # name contains interesting patterns often useful for fuzz harnesses
            if self.interesting_name:
                score += 1.0

        # function signature can directly consume fuzzer input
        if self.has_risky_sink:
            score += 1.0

        """
        # function achieved an optimal threshold of coverage to be fuzzed
        depth_threshold = int(Settings().get_string("fuzzable.depth_threshold"))
        if self.depth >= depth_threshold:
            score += 1.0

        # contains loop won't change score if configured
        loop_increase = Settings().get_bool("fuzzable.loop_increase_score")
        if not loop_increase and self.has_loop:
            score += 1.0
        """

        # auxiliary: recursive call doesn't change score, but useful information
        return score