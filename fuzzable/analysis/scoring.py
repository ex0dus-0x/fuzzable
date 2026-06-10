"""
scoring.py

    Fuzzability ranking via entropy-weighted TOPSIS.

    This module treats ranking as a multi-criteria decision analysis (MCDA)
    problem with four well-defined stages:

        1. Measure   - read the raw per-function metric matrix (never mutated).
        2. Transform - log1p each feature to tame heavy-tailed counts.
        3. Weight    - objective Shannon-entropy weights derived from the data,
                       unless the caller supplies explicit weights.
        4. Aggregate - TOPSIS: score each function by its relative closeness to the
                       ideal (best-on-every-metric) vs. anti-ideal solution.

    TOPSIS is used because it is scale-robust after vector normalization, considers
    both the best and worst attainable values, and yields a bounded closeness score
    in [0, 1] that we surface as a 0-100 fuzzability score.

    References:
        - Hwang & Yoon (1981), "Multiple Attribute Decision Making" (TOPSIS).
        - Zhang et al. (2011), entropy weighting for objective MCDA.
"""

import math

from .metrics import METRICS, Direction, MetricSpec
from .model import CallScore


def rank_fuzzability(
    scores: list[CallScore],
    weights: list[float] | None = None,
) -> list[CallScore]:
    """
    Score and rank function targets by fuzzability.

    Args:
        scores: analyzed functions with their ``features`` populated.
        weights: optional explicit weights (positional to ``features.METRICS``).
            When ``None``, objective entropy weights are derived from the data.

    Returns the same ``CallScore`` objects sorted best-first, with ``score``
    (0-100), ``rank`` (1-based), and per-metric ``contributions`` populated.
    """
    if not scores:
        return scores

    # the features actually present this run (uniform per backend), in canonical order
    active = [feature for feature in METRICS if feature.id in scores[0].features]
    ids = [feature.id for feature in active]

    # a single candidate has nothing to be ranked relative to
    if len(scores) == 1:
        only = scores[0]
        only.score = 100.0
        only.rank = 1
        only.contributions = dict.fromkeys(ids, 0.0)
        return scores

    transformed = _transform(_raw_matrix(scores, ids))

    if weights is not None:
        used_weights = _normalize_weights(_align_weights(weights, active))
    else:
        used_weights = _entropy_weights(transformed)

    directions = [feature.direction for feature in active]
    closeness, weighted_norm = _topsis(transformed, used_weights, directions)

    ranked = sorted(
        zip(scores, closeness, weighted_norm),
        key=lambda item: item[1],
        reverse=True,
    )

    for position, (score, closeness_value, contribution) in enumerate(ranked, start=1):
        score.score = round(closeness_value * 100.0, 2)
        score.rank = position
        score.contributions = {
            fid: round(value, 4) for fid, value in zip(ids, contribution)
        }

    return [score for score, _, _ in ranked]


def _align_weights(weights: list[float], active: list[MetricSpec]) -> list[float]:
    """Map weights given positionally over all METRICS onto the active subset."""
    by_id = {METRICS[i].id: weights[i] for i in range(min(len(weights), len(METRICS)))}
    return [by_id.get(feature.id, 0.0) for feature in active]


def _raw_matrix(scores: list[CallScore], ids: list[str]) -> list[list[float]]:
    """Build the n-functions x m-features matrix from the results' feature values."""
    return [[float(score.features[fid]) for fid in ids] for score in scores]


def _transform(matrix: list[list[float]]) -> list[list[float]]:
    """
    Apply log1p to every feature. Metrics like coverage depth and cyclomatic
    complexity are heavy-tailed counts; a log transform compresses outliers so a
    single huge function cannot flatten everyone else during normalization.
    """
    return [[math.log1p(value) for value in row] for row in matrix]


def _entropy_weights(matrix: list[list[float]]) -> list[float]:
    """
    Objective Shannon-entropy weighting.

    Each criterion's weight is proportional to its information content: a feature
    that varies a lot across candidates is discriminating and gets more weight; a
    near-constant feature carries little information and is down-weighted. This
    removes the arbitrariness of hand-picked weights.
    """
    n = len(matrix)
    m = len(matrix[0])
    k = 1.0 / math.log(n)  # n >= 2 guaranteed by the caller

    diversification = [0.0] * m
    for j in range(m):
        column = [matrix[i][j] for i in range(n)]
        total = sum(column)
        if total <= 0.0:
            # constant/all-zero column carries no information
            diversification[j] = 0.0
            continue

        entropy = 0.0
        for value in column:
            if value > 0.0:
                proportion = value / total
                entropy -= proportion * math.log(proportion)
        entropy *= k
        diversification[j] = 1.0 - entropy

    total_diversification = sum(diversification)
    if total_diversification <= 0.0:
        # no feature discriminates -> fall back to equal weights
        return [1.0 / m] * m

    return [d / total_diversification for d in diversification]


def _normalize_weights(weights: list[float]) -> list[float]:
    """Normalize caller-supplied weights to sum to 1."""
    if not weights:
        return weights
    total = sum(weights)
    if total <= 0.0:
        return [1.0 / len(weights)] * len(weights)
    return [w / total for w in weights]


def _topsis(
    matrix: list[list[float]],
    weights: list[float],
    directions: list[Direction],
) -> tuple[list[float], list[list[float]]]:
    """
    Technique for Order Preference by Similarity to Ideal Solution.

    Returns each function's closeness coefficient in [0, 1] and the weighted
    normalized matrix (used as per-metric contributions for explainability).
    """
    n = len(matrix)
    m = len(matrix[0])

    # vector (L2) normalization makes columns scale-invariant and comparable
    column_norms = [
        math.sqrt(sum(matrix[i][j] ** 2 for i in range(n))) for j in range(m)
    ]
    weighted = [
        [
            (matrix[i][j] / column_norms[j] if column_norms[j] > 0 else 0.0)
            * weights[j]
            for j in range(m)
        ]
        for i in range(n)
    ]

    # the ideal is the best attainable per criterion: max for benefit, min for cost
    column_max = [max(weighted[i][j] for i in range(n)) for j in range(m)]
    column_min = [min(weighted[i][j] for i in range(n)) for j in range(m)]
    benefit = [d is Direction.BENEFIT for d in directions]
    ideal = [column_max[j] if benefit[j] else column_min[j] for j in range(m)]
    anti_ideal = [column_min[j] if benefit[j] else column_max[j] for j in range(m)]

    closeness = []
    for i in range(n):
        dist_ideal = math.sqrt(sum((weighted[i][j] - ideal[j]) ** 2 for j in range(m)))
        dist_anti = math.sqrt(
            sum((weighted[i][j] - anti_ideal[j]) ** 2 for j in range(m))
        )
        denominator = dist_ideal + dist_anti
        closeness.append(dist_anti / denominator if denominator > 0 else 0.0)

    return closeness, weighted
