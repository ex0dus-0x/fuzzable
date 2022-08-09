"""
__init__.py

    Implements the base class and exception for different static analysis backends.
"""

import abc
import enum
import typing as t

SCIKIT = True
try:
    import skcriteria as skc
    from skcriteria.madm import simple
except Exception:
    SCIKIT = False

from ..metrics import CallScore
from ..config import INTERESTING_PATTERNS, RISKY_GLIBC_CALL_PATTERNS

# Type sig for a finalized list
Fuzzability = t.OrderedDict[str, CallScore]

# Default weights for fuzzability
DEFAULT_SCORE_WEIGHTS: t.List[float] = [0.3, 0.3, 0.05, 0.05, 0.3]


class AnalysisException(Exception):
    """Raised when an analysis fails to succeed."""


class AnalysisMode(enum.Enum):
    """Describes how we should analyze targets and present results."""

    RECOMMEND = 0
    RANK = 1


class AnalysisBackend(abc.ABC):
    """Base class for analysis backends to implement and detect fuzzable targets."""

    def __init__(
        self,
        target: t.Any,
        mode: AnalysisMode,
        score_weights: t.List[float] = DEFAULT_SCORE_WEIGHTS,
    ):
        self.target = target
        self.mode = mode

        # weights of each feature for MCDA
        self.score_weights = score_weights

        # mapping of functions + locations we've chosen to skipped
        self.skipped: t.Dict[str, str] = {}

        # stores all the scores we've measured from the functions
        self.scores: t.List[t.Any] = []

        # caches names of calls we've visited already to skip repeats
        self.visited: t.List[t.Any] = []

    @abc.abstractmethod
    def __str__(self) -> str:
        ...

    @abc.abstractmethod
    def run(self) -> Fuzzability:
        """
        Determine the fuzzability of each function in the binary or source targets.
        If the mode to recommend targets, determine and statically analyze only top-level calls.
        If the mode is to rank targets, iterate and analyze over all calls and rank.
        """
        ...

    def _rank_fuzzability(self, unranked: t.List[CallScore]) -> Fuzzability:
        """
        After analyzing each function call, use scikit-criteria to rank based on the call score
        using a simple weighted-sum model.

        This should be the tail call for run, as it produces the finalized results
        """

        # TODO: deprecate this.
        if not SCIKIT:
            return self._rank_simple_fuzzability(unranked)

        # normalize
        nl_normalized = AnalysisBackend._normalize(
            [score.natural_loops for score in unranked]
        )
        for score, new_nl in zip(unranked, nl_normalized):
            score.natural_loops = new_nl

        cc_normalized = AnalysisBackend._normalize(
            [score.cyclomatic_complexity for score in unranked]
        )
        for score, new_cc in zip(unranked, cc_normalized):
            score.cyclomatic_complexity = new_cc

        # construct our matrix
        matrix = [score.matrix_row for score in unranked]
        names = [score.name for score in unranked]

        objectives = [max, max, max, max, max]
        decision_matrix = skc.mkdm(
            matrix,
            objectives,
            weights=self.score_weights,
            alternatives=names,
            criteria=[
                "fuzz_friendly",
                "sinks",
                "loop",
                "coverage",
                "cyclomatic_complexity",
            ],
        )

        dec = simple.WeightedSumModel()
        rank = dec.evaluate(decision_matrix)

        # TODO make this better

        # finalize CallScores by setting scores and ranks
        scores = rank.e_.score
        ranks = list(rank.rank_)
        new_unranked = []
        for rank, score, entry in zip(ranks, scores, unranked):
            entry.rank = rank
            entry.score = score
            new_unranked += [entry]

        # can sort our unranked list appropriately now
        sorted_results = [y for _, y in sorted(zip(ranks, new_unranked))]
        return sorted_results

    def _rank_simple_fuzzability(self, unranked: t.List[CallScore]) -> Fuzzability:
        nl_normalized = AnalysisBackend._normalize(
            [score.natural_loops for score in unranked]
        )
        for score, new_nl in zip(unranked, nl_normalized):
            score.natural_loops = new_nl

        cc_normalized = AnalysisBackend._normalize(
            [score.cyclomatic_complexity for score in unranked]
        )
        for score, new_cc in zip(unranked, cc_normalized):
            score.cyclomatic_complexity = new_cc

        return sorted(unranked, key=lambda obj: obj.simple_fuzzability, reverse=True)

    @staticmethod
    def _normalize(lst: t.List[int]) -> t.List[int]:
        """Normalize values in a list based on upper and lower bounds"""
        xmin = min(lst)
        xmax = max(lst)
        for i, val in enumerate(lst):
            if (xmax - xmin) != 0:
                lst[i] = (val - xmin) / (xmax - xmin)

        return lst

    @abc.abstractmethod
    def analyze_call(self, name: str, func: t.Any) -> CallScore:
        """
        Runs heuristics we declare below on an individual function call, and
        return a `CallScore` describing heuristics matched.
        """
        ...

    @abc.abstractmethod
    def skip_analysis(self, func: t.Any) -> bool:
        """
        Helper to determine if a parsed function should be skipped
        for analysis based on certain criteria for the analysis backend.
        """
        ...

    @staticmethod
    def is_fuzz_friendly(symbol_name: str) -> int:
        """
        FUZZABILITY HEURISTIC

        Analyze the function's name to see if it is "fuzzer entry friendly". This denotes
        a function that can easily be called to consume a buffer filled by the fuzzer, or
        a string pointing to a filename, which can also be supplied through a file fuzzer.
        """
        return [
            pattern in symbol_name.lower() for pattern in INTERESTING_PATTERNS
        ].count(True)

    @abc.abstractmethod
    def is_toplevel_call(self, target: t.Any) -> bool:
        """
        Checks to see if the function is top-level, aka is not invoked by any other function
        in the current binary/codebase context.
        """
        ...

    @abc.abstractmethod
    def risky_sinks(self, func: t.Any) -> int:
        """
        HEURISTIC
        Checks to see if one or more of the function's arguments is
        potentially user-controlled, and flows into an abusable call.
        """
        ...

    @staticmethod
    def _is_risky_call(name: str) -> bool:
        """Helper to see if a function call deems potentially risky behaviors."""
        return any([pattern in name.lower() for pattern in RISKY_GLIBC_CALL_PATTERNS])

    @abc.abstractmethod
    def get_coverage_depth(self, func: t.Any) -> int:
        """
        HEURISTIC
        Calculates and returns a `CoverageReport` that highlights how much
        a fuzzer would ideally explore at different granularities.
        """
        ...

    @abc.abstractmethod
    def natural_loops(self, func: t.Any) -> int:
        """
        HEURISTIC
        Detection of loops is at a basic block level by checking the dominance frontier,
        which denotes the next successor the current block node will definitely reach. If the
        same basic block exists in the dominance frontier set, then that means the block will
        loop back to itself at some point in execution.
        """
        ...

    @abc.abstractmethod
    def get_cyclomatic_complexity(self) -> int:
        """
        HEURISTIC
        Calculates the complexity of a given function using McCabe's metric. We do not
        account for connected components since we assume that the target is a singular
        connected component.

        CC = Edges − Nodes/Blocks + 2
        """
        ...
