"""
test_main.py

    Tests main functionality, including
"""

import unittest

from pathlib import Path

from fuzzable.analysis import AnalysisMode
from fuzzable.analysis.angr import AngrAnalysis
from fuzzable.analysis.ast import AstAnalysis


class TestMain(unittest.TestCase):
    def test_basic(self):
        data = [1, 2, 3]
        result = sum(data)
        self.assertEqual(result, 6)

    def test_analysis_binary(self):
        target = Path("examples/binaries/libbasic.so.1")
        analyzer = AngrAnalysis(target, mode=AnalysisMode.RANK)
        analyzer.run()

    def test_analysis_source_file(self):
        target = Path("examples/source/libbasic.c")
        analyzer = AstAnalysis([target], mode=AnalysisMode.RANK)
        analyzer.run()

    def test_analysis_source_folder(self):
        target = Path("examples/source/libyaml")
        analyzer = AstAnalysis(target, mode=AnalysisMode.RANK)
        analyzer.run()


if __name__ == "__main__":
    unittest.main()
