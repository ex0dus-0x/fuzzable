"""
ast.py

    Fuzzable analysis support for C/C++ code by through query on top of pycparser ASTs.

"""
import typing as t

from tree_sitter import Language, Node, Parser

from . import AnalysisBackend, AnalysisMode, Fuzzability
from ..metrics import CallScore

BUILD_PATH = "build/lang.so"


class AstAnalysis(AnalysisBackend):
    """Derived class to support parsing C/C++ ASTs with pycparser"""

    def __init__(self, target: t.List[str], mode: AnalysisMode):
        Language.build_library(
            BUILD_PATH,
            ["third_party/tree-sitter-c", "third_party/tree-sitter-cpp"],
        )
        self.language = Language(BUILD_PATH, "c")
        self.parser = Parser()
        super().__init__(target, mode)

    def __str__(self) -> str:
        return "tree-sitter"

    def run(self) -> Fuzzability:
        for filename in self.target:

            # switch over language if different language detected
            if filename.suffix in [".cpp", ".cc", ".hpp", ".hh"]:
                self.language = Language(BUILD_PATH, "cpp")
            else:
                self.language = Language(BUILD_PATH, "c")

            self.parser.set_language(self.language)

            with open(filename, "rb") as fd:
                contents = fd.read()

            tree = self.parser.parse(contents)
            # print(tree.root_node.sexp())

            query = self.language.query(
                """
            (function_definition) @capture
            """
            )
            self.parsed_symbols += [query.captures(tree.root_node)]

        # now analyze each function_definition node
        for func in self.parsed_symbols:
            if self.skip_analysis(func):
                continue
    
            # if recommend mode, filter and run only those that are top-level
            if self.mode == AnalysisMode.RECOMMEND and not self.is_toplevel_call(func):
                continue

            # get function name from the node
            query = self.language.query(
                """
            (identifier) @capture
            """
            )
            name = query.captures(func)
            score = [self.analyze_call(name, func)]

            self.scores += [score]

        ranked = super()._rank_fuzzability(self.scores)
        return ranked

    def analyze_call(self, name: str, func: Node) -> CallScore:
        return CallScore(
            name=name,
            toplevel=self.is_toplevel_call(func),
            fuzz_friendly=AstAnalysis.is_fuzz_friendly(name),
            risky_sinks=self.risky_sinks(func),
            contains_loop=AstAnalysis.contains_loop(func),
            coverage_depth=self.get_coverage_depth(func),
        )

    def skip_analysis(self, func: t.Any) -> bool:
        """
        TODO
        - match on standard library calls
        - skip inlined calls
        """
        return False

    def is_toplevel_call(self, target: t.Any) -> bool:
        """
        TODO
        - check if node is a callee of any other nodes cached currently
        """
        for node in self.parsed_symbols:
            query = self.language.query(
                """
            (function_definition) @capture
            """
            )
            query.captures(node)

        return False

    def risky_sinks(self, func: t.Any) -> int:
        pass

    def get_coverage_depth(self, func: t.Any) -> int:
        pass

    def contains_loop(self, func: t.Any) -> bool:
        pass

    def get_cyclomatic_complexity(self) -> int:
        """
        HEURISTIC

        M = E − N + 2P
        """
        pass
