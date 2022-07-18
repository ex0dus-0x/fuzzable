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

        # number of functions not analyzed
        self.skipped: int = 0

        self.scores: t.List[t.Any] = []
        self.visited: t.List[t.Any] = []

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
        After analyzing each function call, use scikit-criteria to rank based on the call score
        using a simple weighted-sum model.

        This should be the tail call for run, as it produces the finalized results
        """

        # TODO: deprecate this.
        if not SCIKIT:
            return self._rank_simple_fuzzability(unranked)

        matrix = [score.matrix_row for score in unranked]
        names = [score.name for score in unranked]

        objectives = [max, max, max, max, max]
        dm = skc.mkdm(
            matrix,
            objectives,
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
        rank = dec.evaluate(dm)

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
        return sorted(unranked, key=lambda x: x.simple_fuzzability, reverse=True)

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
        return any([pattern in name.lower() for pattern in RISKY_GLIBC_CALL_PATTERNS])

    @abc.abstractmethod
    def get_coverage_depth(self, func: t.Any) -> int:
        """
        HEURISTIC
        Calculates and returns a `CoverageReport` that highlights how much
        a fuzzer would ideally explore at different granularities.
        """
        pass

    @abc.abstractmethod
    def natural_loops(self, func: t.Any) -> int:
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
