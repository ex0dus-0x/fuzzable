"""
test_miasm.py

    Tests the miasm-backed binary analysis against a small committed ELF fixture
    (an x86_64 shared object built from examples/libbasic.c).
"""

import unittest
from pathlib import Path

from fuzzable.backend.miasm import MiasmAnalysis

FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "libbasic.so"


class TestMiasmAnalysis(unittest.TestCase):
    def test_analysis_binary(self):
        analyzer = MiasmAnalysis(FIXTURE, include_nontop=True)

        # the fixture exposes exactly the three example functions
        self.assertEqual(
            set(analyzer.functions),
            {"vulnerable_parse_buf", "free_obj", "not_so_vulnerable"},
        )

        results = analyzer.rank()
        self.assertEqual(len(results), 3)

        # the vulnerable parser is the strongest fuzzing candidate, and its name
        # is the most fuzz-friendly of the three (matches "parse" and "buf")
        self.assertEqual(results[0].name, "vulnerable_parse_buf")
        self.assertEqual(results[0].features["fuzz_friendly"], 2)

        # none of the exported library functions call each other, so all are top-level
        self.assertTrue(all(score.toplevel for score in results))


if __name__ == "__main__":
    unittest.main()
