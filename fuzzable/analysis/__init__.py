"""
__init__.py

    Base provider and the generic analysis pipeline.

    A backend implements ``discover()`` to yield
    :class:`fuzzable.model.Function` objects. The shared ``run()`` then filters,
    scores every applicable feature, and ranks.
"""

import abc
import typing as t

from ..log import log
from .metrics import Capability, active_features
from .model import CallScore, Function

# Type sig for a finalized list
Fuzzability = t.OrderedDict[str, CallScore]

# Don't-care symbols during the initial walk
GLOBAL_IGNORES: list[str] = [
    "__cxa_finalize",
    "__gmon_start__",
    "_init",
    "_fini",
    "frame_dummy",
    "call_weak_fn",
    "register_tm_clones",
    "$x",
]


class AnalysisException(Exception):
    """Raised when an analysis fails to succeed."""


class AnalysisBackend(abc.ABC):
    """Base provider: discovers function targets and runs the scoring pipeline."""

    # analysis capabilities this backend offers; gates which features it computes
    capabilities: Capability = Capability.NONE

    def __init__(
        self,
        include_sym: list[str] = [],
        include_nontop: bool = False,
        skip_sym: list[str] = [],
        skip_stripped: bool = False,
        score_weights: list[float] | None = None,
    ):
        # configures inclusion
        self.include_sym: list[str] = include_sym
        self.include_nontop: bool = include_nontop

        # configures exclusion
        self.skip_sym: list[str] = skip_sym
        self.skip_stripped: bool = skip_stripped

        # explicit per-metric weights; when None, ranking derives objective
        # entropy weights from the analyzed functions (see scoring.py)
        self.score_weights: list[float] | None = score_weights

        # function name -> location for symbols we chose to skip
        self.skipped: dict[str, str] = {}

        # finalized scores, and names already seen (dedup)
        self.scores: list[CallScore] = []
        self.visited: list[str] = []

    @abc.abstractmethod
    def __str__(self) -> str: ...

    @abc.abstractmethod
    def yield_candidate(self) -> t.Iterable[Function]:
        """Yield each analyzable function in the target as a normalized model."""
        ...

    def rank(self) -> Fuzzability:
        """Generic pipeline: discover -> filter -> score features -> rank."""
        log.info("Discovering and scoring function targets")
        for function in self.yield_candidate():
            if function.name in self.visited:
                continue
            self.visited += [function.name]

            if self.skip_analysis(function.name):
                self.skipped[function.name] = function.location
                continue

            if not self.include_nontop and not function.is_top_level:
                log.warning(
                    f"Skipping {function.name} (not top-level)."
                )
                self.skipped[function.name] = function.location
                continue

            log.info(f"Scoring function {function.name}")
            self.scores += [self._score(function)]

        if len(self.scores) == 0:
            raise AnalysisException(
                "no function targets parsed for ranking"
            )

        # imported lazily to avoid a circular import at package init
        from .scoring import rank_fuzzability

        log.info("Ranking symbols by fuzzability")
        return rank_fuzzability(self.scores, self.score_weights)

    def _score(self, function: Function) -> CallScore:
        """Compute every applicable feature for a function into a CallScore."""
        features = {
            spec.id: float(spec.compute(function))
            for spec in active_features(function.capabilities)
        }
        return CallScore(
            name=function.name,
            loc=function.location,
            toplevel=function.is_top_level,
            stripped=function.stripped,
            features=features,
        )

    def skip_analysis(self, name: str) -> bool:
        """Whether a parsed function should be excluded from analysis."""
        # explicitly requested for inclusion
        if name in self.include_sym:
            return False

        if name in self.skip_sym:
            log.warning(f"Skipping {function.name} (explicitly excluded)")
            return True

        if "sub_" in name and self.skip_stripped:
            log.warning(f"Skipping {function.name} (stripped)")
            return True

        if name in GLOBAL_IGNORES or name.startswith("__"):
            log.warning(f"Skipping {function.name} (don't care)")
            return True

        return False
