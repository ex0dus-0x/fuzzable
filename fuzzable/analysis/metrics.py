"""
metrics.py

    Structured representation of a metric that can be ingested for MCDA.
"""

import enum
import typing as t
from dataclasses import dataclass

if t.TYPE_CHECKING:
    from .model import Function


class Direction(enum.Enum):
    """Whether a higher feature value is good (benefit) or bad (cost) for ranking."""

    BENEFIT = "benefit"
    COST = "cost"


class Capability(enum.Flag):
    """Analysis capabilities a backend can offer, gating which features apply."""

    NONE = 0
    NAME = enum.auto()  # a symbol name is available
    TYPES = enum.auto()  # parameter types are recovered
    CFG = enum.auto()  # a basic-block control-flow graph is available
    CALLS = enum.auto()  # an intra-target call graph is available
    DATAFLOW = enum.auto()  # taint / def-use analysis is available


# Symbol-name substrings that suggest a function ingests fuzzer-controllable input.
INTERESTING_PATTERNS: tuple[str, ...] = (
    "parse",
    "read",
    "buf",
    "file",
    "input",
    "str",
    "encode",
    "decode",
    "draw",
    "image",
    "img",
    "load",
    "url",
)


def _input_surface(function: "Function") -> float:
    """Attack surface from parameter types: buffers, files, and (buf, len) pairs."""
    score = 0
    has_buffer = False
    has_size = False
    for param in function.parameters:
        if param.is_file:
            score += 2
        elif param.points_to_bytes:
            score += 1
            has_buffer = True
        if param.is_integral:
            has_size = True
    if has_buffer and has_size:
        score += 1  # classic (buffer, length) signature
    return float(score)


def _fuzz_friendly(function: "Function") -> float:
    """Count of fuzzer-friendly substrings present in the function name."""
    name = function.name.lower()
    return float(sum(1 for pattern in INTERESTING_PATTERNS if pattern in name))


def _measure(feature_id: str) -> t.Callable[["Function"], float]:
    """Passthrough to a provider-computed value exposed via ``Function.measures``."""

    def compute(function: "Function") -> float:
        thunk = function.measures.get(feature_id)
        return float(thunk()) if thunk is not None else 0.0

    return compute


@dataclass(frozen=True)
class MetricSpec:
    """Declarative description of a single fuzzability feature."""

    id: str
    label: str
    compute: t.Callable[["Function"], float]
    direction: Direction = Direction.BENEFIT
    requires: Capability = Capability.NONE


# Order here defines the display/scoring order and the positional meaning of
# explicit --score-weights.
METRICS: tuple[MetricSpec, ...] = (
    MetricSpec(
        "input_surface", "Input Surface", _input_surface, requires=Capability.TYPES
    ),
    MetricSpec(
        "fuzz_friendly", "Fuzz-Friendly Name", _fuzz_friendly, requires=Capability.NAME
    ),
    MetricSpec(
        "taint_influence",
        "Taint Influence",
        _measure("taint_influence"),
        requires=Capability.DATAFLOW,
    ),
    MetricSpec(
        "natural_loops",
        "Natural Loops",
        _measure("natural_loops"),
        requires=Capability.CFG,
    ),
    MetricSpec(
        "cyclomatic_complexity",
        "Cyclomatic Complexity",
        _measure("cyclomatic_complexity"),
        requires=Capability.CFG,
    ),
    MetricSpec(
        "coverage_depth",
        "Coverage Depth",
        _measure("coverage_depth"),
        requires=Capability.CALLS,
    ),
)

METRIC_IDS: tuple[str, ...] = tuple(feature.id for feature in METRICS)


def active_features(capabilities: Capability) -> tuple[MetricSpec, ...]:
    """Return the features computable given a backend's capabilities."""
    return tuple(
        feature
        for feature in METRICS
        if (feature.requires & capabilities) == feature.requires
    )
