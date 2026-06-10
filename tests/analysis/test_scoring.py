"""
test_scoring.py

    Unit tests for the entropy-weighted TOPSIS fuzzability ranker.
"""

import unittest

from fuzzable.analysis.scoring import _entropy_weights, rank_fuzzability
from fuzzable.analysis.metrics import METRIC_IDS
from fuzzable.analysis.model import CallScore


def make_score(
    name: str,
    input_surface: int = 0,
    fuzz_friendly: int = 0,
    taint_influence: float = 0.0,
    natural_loops: int = 0,
    cyclomatic_complexity: int = 0,
    coverage_depth: int = 0,
) -> CallScore:
    return CallScore(
        name=name,
        loc="0x0",
        toplevel=True,
        stripped=False,
        features={
            "input_surface": input_surface,
            "fuzz_friendly": fuzz_friendly,
            "taint_influence": taint_influence,
            "natural_loops": natural_loops,
            "cyclomatic_complexity": cyclomatic_complexity,
            "coverage_depth": coverage_depth,
        },
    )


class TestScoring(unittest.TestCase):
    def test_basic_invariants(self):
        scores = [
            make_score("a", fuzz_friendly=2, taint_influence=0.4, coverage_depth=5),
            make_score("b", coverage_depth=3),
            make_score("c", cyclomatic_complexity=4, natural_loops=1),
        ]
        ranked = rank_fuzzability(scores)

        # ranks are a 1..n permutation, scores bounded, contributions populated
        self.assertEqual(sorted(s.rank for s in ranked), [1, 2, 3])
        for s in ranked:
            self.assertGreaterEqual(s.score, 0.0)
            self.assertLessEqual(s.score, 100.0)
            self.assertEqual(set(s.contributions), set(METRIC_IDS))
        # output is sorted best-first
        self.assertEqual([s.rank for s in ranked], [1, 2, 3])

    def test_high_coverage_noise_does_not_dominate(self):
        """
        Regression for the original scale-mixing bug: a function strong only in
        raw coverage_depth used to outrank a genuinely risky, fuzz-friendly target.
        """
        vuln = make_score(
            "vulnerable_parse_buf",
            fuzz_friendly=2,
            taint_influence=0.5,
            natural_loops=1,
            cyclomatic_complexity=3,
            coverage_depth=5,
        )
        noise = make_score("runtime_blob", coverage_depth=130)
        plain = make_score("plain", cyclomatic_complexity=1, coverage_depth=1)

        ranked = rank_fuzzability([noise, plain, vuln])
        by_name = {s.name: s for s in ranked}

        self.assertEqual(ranked[0].name, "vulnerable_parse_buf")
        self.assertLess(
            by_name["vulnerable_parse_buf"].rank, by_name["runtime_blob"].rank
        )

    def test_raw_metrics_are_not_mutated(self):
        vuln = make_score("v", cyclomatic_complexity=7, natural_loops=3)
        other = make_score("o", coverage_depth=4)
        rank_fuzzability([vuln, other])

        # scoring must not overwrite the interpretable raw measurements
        self.assertEqual(vuln.features["cyclomatic_complexity"], 7)
        self.assertEqual(vuln.features["natural_loops"], 3)

    def test_entropy_zero_weight_for_constant_feature(self):
        # column 0 is constant (no information), column 1 varies
        matrix = [[1.0, 1.0], [1.0, 5.0], [1.0, 10.0]]
        weights = _entropy_weights(matrix)

        self.assertAlmostEqual(weights[0], 0.0, places=9)
        self.assertAlmostEqual(weights[1], 1.0, places=9)
        self.assertAlmostEqual(sum(weights), 1.0, places=9)

    def test_manual_weights_override(self):
        # weight everything on fuzz_friendly (index 1) -> highest fuzz_friendly wins
        a = make_score("a", fuzz_friendly=5, coverage_depth=1)
        b = make_score("b", fuzz_friendly=0, coverage_depth=100)
        ranked = rank_fuzzability([b, a], weights=[0, 1, 0, 0, 0, 0])
        self.assertEqual(ranked[0].name, "a")

    def test_single_function_is_handled(self):
        only = make_score("solo", fuzz_friendly=1)
        ranked = rank_fuzzability([only])
        self.assertEqual(len(ranked), 1)
        self.assertEqual(ranked[0].rank, 1)
        self.assertEqual(ranked[0].score, 100.0)


if __name__ == "__main__":
    unittest.main()
