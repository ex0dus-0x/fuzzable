"""
model.py

    Models of program features that analysis providers produce.
"""

import functools
import typing as t
from dataclasses import asdict, dataclass, field

from .metrics import METRICS


def once(thunk: t.Callable[[], t.Any]) -> t.Callable[[], t.Any]:
    """Memoize a zero-argument callable so repeated feature reads compute it once."""
    return functools.lru_cache(maxsize=1)(thunk)


@dataclass(frozen=True)
class Parameter:
    """A normalized function parameter, enough to score attack surface."""

    name: str = ""
    points_to_bytes: bool = False  # char*/void*/uint8_t* etc.
    is_integral: bool = False  # int/size_t/... (candidate length)
    is_file: bool = False  # FILE*


@dataclass
class Function:
    """A function target in a backend-independent shape."""

    name: str
    location: str

    # the analysis capabilities available for this function (gates features)
    capabilities: t.Any

    # not invoked by anything else in the target (an ideal fuzzing entry point)
    is_top_level: bool = True

    # symbol was stripped (binary analysis)
    stripped: bool = False

    # normalized parameters, used by the shared input-surface feature
    parameters: list[Parameter] = field(default_factory=list)

    # provider-computed, backend-specific feature thunks keyed by feature id
    measures: dict[str, t.Callable[[], float]] = field(default_factory=dict)

    # native handle (clang cursor, miasm asmcfg, BN function) for power features
    raw: t.Any = None


@dataclass
class CallScore:
    """Fuzzability result for a single function target."""

    name: str
    loc: str

    # does not attribute to rank, but helps with determining what to filter
    toplevel: bool

    # does not attribute to rank, but helps with binary analysis
    stripped: bool | None

    # feature id -> measured value (see features.METRICS)
    features: dict[str, float]

    # mutable values set after analysis
    _final_rank: int = field(init=False, repr=False)
    _final_score: float = field(init=False, repr=False)

    # per-metric weighted contribution to the final score (explainability)
    contributions: dict[str, float] = field(default_factory=dict, repr=False)

    @property
    def rank(self) -> int:
        """Rank of an individual function in a list of parsed functions"""
        return self._final_rank

    @rank.setter
    def rank(self, to_set: int) -> None:
        self._final_rank = int(to_set)

    @property
    def score(self) -> float:
        """Final calculated fuzzability score based on metrics"""
        return self._final_score

    @score.setter
    def score(self, to_set: float) -> None:
        self._final_score = float(to_set)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, CallScore):
            return NotImplemented
        return self._final_score == other._final_score

    def __lt__(self, other: "CallScore") -> bool:
        return self._final_score < other._final_score

    def __gt__(self, other: "CallScore") -> bool:
        return self._final_score > other._final_score

    def asdict(self) -> dict[str, t.Any]:
        return asdict(self)

    def _feature_cells(self) -> list[str]:
        """Feature values in canonical METRICS order (blank if not measured)."""
        return [
            str(self.features[feature.id]) if feature.id in self.features else ""
            for feature in METRICS
        ]

    @property
    def binja_markdown_row(self) -> str:
        """Output as a markdown/ascii table row when displaying back to user"""
        cells = " | ".join(self._feature_cells())
        return (
            f"| [{self.name}](binaryninja://?expr={self.name}) | {self.loc} | "
            f"{self.score} | {cells} | \n"
        )

    @property
    def csv_row(self) -> str:
        """Generate a CSV row for exporting to file"""
        cells = [self.name, self.loc, str(self.stripped)]
        cells += self._feature_cells()
        cells += [str(self.score)]
        return ",".join(cells) + "\n"
