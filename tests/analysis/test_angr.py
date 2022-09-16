"""
test_angr.py
"""
import unittest
from pathlib import Path

from fuzzable.analysis.angr import AngrAnalysis


class TestAngrAnalysis(unittest.TestCase):
    def test_basic(self):
        data = [1, 2, 3]
        result = sum(data)
        self.assertEqual(result, 6)

    #def test_angr_analysis(self):
    #    analyzer = AngrAnalysis()


if __name__ == "__main__":
    unittest.main()
