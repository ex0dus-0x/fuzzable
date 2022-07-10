"""
metrics.py

    Dataclass definitions for various metrics collected during qthe risk analysis.
"""
import functools
import typing as t

from dataclasses import dataclass


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

    # does not attribute to rank, but helps with determining what to filter
    toplevel: bool

    # does not attribute to rank, but helps with binary analysis
    stripped: t.Optional[bool]

    # quantifies the number of fuzzer friendly words that exist in the target's name
    fuzz_friendly: int

    # quantifies the number of fuzzer arguments that flow into
    risky_sinks: int

    # TODO: cyclomatic complexity
    contains_loop: int

    # represents coverage by different granularities
    #coverage_depth: CoverageReport
    coverage_depth: int

    @property
    def table_row(self) -> str:
        """Output as a markdown/ascii table row when displaying back to user"""
        return f"| [{self.name}](binaryninja://?expr={self.name}) | {self.fuzzability} | {self.depth} | {self.contains_loop} | {self.recursive} | \n"

    @property
    def csv_row(self) -> str:
        """Generate a CSV row for exporting to file"""
        return f"{self.name}, {self.stripped}, {self.interesting_name}, {self.interesting_args}, {self.depth}, {self.contains_loop}, {self.fuzzability}\n"

    @functools.cached_property
    def simple_fuzzability(self) -> int:
        """
        Calculate a cached fuzzability score for the given function target based on the analysis metrics.
        """

        score = 0
        if not self.stripped:
            score += 1
        
        score += self.fuzz_friendly
        score += self.risky_sinks

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
        return score