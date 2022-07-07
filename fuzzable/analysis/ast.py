"""
ast.py

    Fuzzable analysis support for C/C++ code by through query
    on top of tree-sitter ASTs.

"""
import typing as t

from tree_sitter import Language, Parser

from fuzzable.analysis import AnalysisBackend, AnalysisMode
from fuzzable.metrics import CallScore, CoverageReport


class AstAnalysis(AnalysisBackend):
    """Derived class"""

    def __str__(self) -> str:
        return "tree-sitter"

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
