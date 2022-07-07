import abc
import enum
import typing as t

from fuzzable.metrics import CallScore, CoverageReport

# Interesting symbol name patterns to check for fuzzable
INTERESTING_PATTERNS: t.List[str] = [
    "Parse",
    "Read",
    "Buf",
    "File",
    "Input",
    "String",
    "Decode",
]

# TODO: dataset of risky function calls
RISKY_GLIBC_CALLS: t.List[str] = []


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

        # list of names to check to against
        self.cached_names: t.List[str] = []

    @abc.abstractmethod
    def __str__(self) -> str:
        pass

    @abc.abstractmethod
    def run(self) -> t.List[CallScore]:
        """
        Determine the fuzzability of each function in the binary or source targets.
        If the mode to recommend targets, determine and statically analyze only top-level calls.
        If the mode is to rank targets, iterate and analyze over all calls and rank.
        """
        pass

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
    @staticmethod
    def is_toplevel_call(target: t.Any) -> bool:
        """
        Checks to see if the function is top-level, aka is not invoked by any other function
        in the current binary/codebase context.
        """
        pass

    @abc.abstractmethod
    @staticmethod
    def has_risky_sink(func: t.Any) -> bool:
        """
        HEURISTIC
        Checks to see if one or more of the function's arguments is
        potentially user-controlled, and flows into an abusable call.
        """
        pass

    @abc.abstractmethod
    @staticmethod
    def get_coverage_depth(func: t.Any) -> CoverageReport:
        """
        HEURISTIC
        Calculates and returns a `CoverageReport` that highlights how much
        a fuzzer would ideally explore at different granularities.
        """
        pass

    @abc.abstractmethod
    @staticmethod
    def contains_loop(func: t.Any) -> bool:
        """
        HEURISTIC
        Detection of loops is at a basic block level by checking the dominance frontier,
        which denotes the next successor the current block node will definitely reach. If the
        same basic block exists in the dominance frontier set, then that means the block will
        loop back to itself at some point in execution.
        """
        pass
