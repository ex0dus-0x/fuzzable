"""
ast.py

    Fuzzable analysis support for C/C++ code by through query
    on top of tree-sitter ASTs.

"""
import typing as t

from pycparser import c_ast, parse_file

from fuzzable.analysis import AnalysisBackend, AnalysisMode
from fuzzable.metrics import CallScore, CoverageReport

class FuncCallVisitor(c_ast.NodeVisitor):
    def __init__(self, funcname):
        self.funcname = funcname

    def visit_FuncCall(self, node):
        if node.name.name == self.funcname:
            print('%s called at %s' % (self.funcname, node.name.coord))
        # Visit args in case they contain more func calls.
        if node.args:
            self.visit(node.args)


def show_func_calls(filename, funcname):
    ast = parse_file(filename, use_cpp=True)
    v = FuncCallVisitor(funcname)
    v.visit(ast)

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
