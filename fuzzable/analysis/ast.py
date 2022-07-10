"""
ast.py

    Fuzzable analysis support for C/C++ code by through query on top of pycparser ASTs.

"""
import sys
import typing as t

from pycparser import c_ast, parse_file

from . import AnalysisBackend, AnalysisMode, Fuzzability
from ..metrics import CallScore, CoverageReport

sys.path.extend(['.', '..'])

class FuncDefVisitor(c_ast.NodeVisitor):
    """
    Visitor for
    """

    def __init__(self):
        self.call_nodes = []

    def visit_FuncDef(self, node):
        print('%s at %s' % (node.decl.name, node.decl.coord))


class AstAnalysis(AnalysisBackend):
    """Derived class to support parsing C/C++ ASTs with pycparser"""

    def __init__(self, target: t.List[str], mode: AnalysisMode):
        super().__init__(target, mode)

    def __str__(self) -> str:
        return "pycparser"

    def run(self) -> Fuzzability:
        analyzed = []
        for filename in self.target:
            ast = parse_file(filename, cpp_path='gcc')

            v = FuncDefVisitor()
            v.visit(ast)

    def analyze_call(self, name: str, func: t.Any) -> CallScore:
        pass

    def skip_analysis(self, func: t.Any) -> bool:
        pass

    def is_toplevel_call(self, target: t.Any) -> bool:
        pass

    def risky_sinks(self, func: t.Any) -> int:
        pass

    def get_coverage_depth(self, func: t.Any) -> int:
        pass

    def contains_loop(self, func: t.Any) -> bool:
        pass
