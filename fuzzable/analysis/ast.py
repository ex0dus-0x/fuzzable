"""
ast.py
"""
from tree_sitter import Language, Parser

from fuzzable.analysis import AnalysisBackend, AnalysisMode
from fuzzable.metrics import CallScore, CoverageReport

class AstAnalysis(AnalysisBackend):
    def run(self) -> t.List[CallScore]:
        pass

    def analyze_call(self, name: str, func: t.Any) -> CallScore:
        pass

    def skip_analysis(self, func: t.Any) -> bool:
        pass

    @staticmethod
    def is_toplevel_call(target: t.Any) -> bool:
        pass

    @staticmethod
    def has_risky_sink(func: t.Any) -> bool:
        pass

    @staticmethod
    def get_coverage_depth(func: t.Any) -> CoverageReport:
        pass

    @staticmethod
    def contains_loop(func: t.Any) -> bool:
        pass