import abc
import dataclasses
import enum
import typing as t

import pandas as pd

from skcriteria.data import Data
from skcriteria.madm import simple

from collections import OrderedDict

from ..metrics import CallScore
from ..config import INTERESTING_PATTERNS, RISKY_GLIBC_CALL_PATTERNS

# Type sig for a finalized list
Fuzzability = t.OrderedDict[str, CallScore]


class AnalysisException(Exception):
    """Raised when an analysis fails to succeed."""


class AnalysisMode(enum.Enum):
    """Describes how we should analyze targets and present results."""

    RECOMMEND = 0
    RANK = 1


class AnalysisBackend(abc.ABC):
    """Base class for analysis backends to implement and detect fuzzable targets."""

    def __init__(self, target: t.Any, mode: AnalysisMode):
        self.target = target
        self.mode = mode

        self.scores: t.List[t.Any] = []

        # stores only the name of the symbol we've already visited, is less expensive
        self.parsed_symbols: t.List[t.Any] = []

    @abc.abstractmethod
    def __str__(self) -> str:
        pass

    @abc.abstractmethod
    def run(self) -> Fuzzability:
        """
        Determine the fuzzability of each function in the binary or source targets.
        If the mode to recommend targets, determine and statically analyze only top-level calls.
        If the mode is to rank targets, iterate and analyze over all calls and rank.
        """
        pass

    def _rank_fuzzability(self, unranked: t.List[CallScore]) -> Fuzzability:
        """
        After analyzing each function call, rank based on the call score

        This should be the tail call for run, as it produces the finalized results
        """
        fuzzability = OrderedDict()
        unranked_df = pd.json_normalize(dataclasses.asdict(obj) for obj in unranked)
        criteria_data = data(
            unranked_df,
            [MAX, MAX, MAX, MAX, MAX],
            anames=function_names,
            cnames=function_names,
        )
        dm = simple.WeightedSum(mnorm="sum")
        dec = dm.decide(criteria_data)
        return dec.asdict()

    @abc.abstractmethod
    def analyze_call(self, name: str, func: t.Any) -> CallScore:
        """
        Runs heuristics we declare below on an individual function call, and
        return a `CallScore` describing heuristics matched.
        """
        pass

    @abc.abstractmethod
    def skip_analysis(self, func: t.Any) -> bool:
        """
        Helper to determine if a parsed function should be skipped
        for analysis based on certain criteria for the analysis backend.
        """
        pass

    @staticmethod
    def is_fuzz_friendly(symbol_name: str) -> bool:
        """
        HEURISTIC
        Analyze the function's name to see if it is "fuzzer entry friendly". This denotes
        a function that can easily be called to consume a buffer filled by the fuzzer, or
        a string pointing to a filename, which can also be supplied through a file fuzzer.
        """
        return any(
            [
                pattern in symbol_name or pattern.lower() in symbol_name
                for pattern in INTERESTING_PATTERNS
            ]
        )

    @abc.abstractmethod
    def is_toplevel_call(self, target: t.Any) -> bool:
        """
        Checks to see if the function is top-level, aka is not invoked by any other function
        in the current binary/codebase context.
        """
        pass

    @abc.abstractmethod
    def risky_sinks(self, func: t.Any) -> int:
        """
        HEURISTIC
        Checks to see if one or more of the function's arguments is
        potentially user-controlled, and flows into an abusable call.
        """
        pass

    @staticmethod
    def _is_risky_call(name: str) -> bool:
        """Helper to see if a function call deems potentially risky behaviors."""
        return any(
            [
                pattern in name or pattern.lower() in name
                for pattern in RISKY_GLIBC_CALL_PATTERNS
            ]
        )

    @abc.abstractmethod
    def get_coverage_depth(self, func: t.Any) -> int:
        """
        HEURISTIC
        Calculates and returns a `CoverageReport` that highlights how much
        a fuzzer would ideally explore at different granularities.
        """
        pass

    @abc.abstractmethod
    def contains_loop(self, func: t.Any) -> bool:
        """
        HEURISTIC
        Detection of loops is at a basic block level by checking the dominance frontier,
        which denotes the next successor the current block node will definitely reach. If the
        same basic block exists in the dominance frontier set, then that means the block will
        loop back to itself at some point in execution.
        """
        pass

    @abc.abstractclassmethod
    def get_cyclomatic_complexity(self) -> int:
        """
        HEURISTIC

        M = E − N + 2P
        """
        pass
