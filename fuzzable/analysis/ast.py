"""
ast.py

    Fuzzable analysis support for C/C++ code by through query on top of tree-sitter ASTs.

"""
import os
import typing as t

from pathlib import Path
from tree_sitter import Language, Node, Parser

from . import AnalysisBackend, Fuzzability, DEFAULT_SCORE_WEIGHTS
from ..metrics import CallScore
from ..log import log
from ..config import get_project_root, SOURCE_FILE_EXTS

# Compiled shared object for language support
BUILD_PATH = os.path.join(get_project_root(), "build/lang.so")


class AstAnalysis(AnalysisBackend):
    """Derived class to support parsing C/C++ ASTs with tree-sitter"""

    def __init__(
        self,
        target: t.List[str],
        include_sym: t.List[str] = [],
        include_nontop: bool = False,
        skip_sym: t.List[str] = [],
        score_weights: t.List[float] = DEFAULT_SCORE_WEIGHTS,
        basedir: t.Optional[Path] = None,
    ):
        super().__init__(target, include_sym, include_nontop, skip_sym, score_weights)

        log.debug("Building third-party tree-sitter libraries for C/C++ languages")
        Language.build_library(
            BUILD_PATH,
            [
                os.path.join(get_project_root(), "third_party/tree-sitter-c"),
                os.path.join(get_project_root(), "third_party/tree-sitter-cpp"),
            ],
        )
        self.language = Language(BUILD_PATH, "c")
        self.parser = Parser()

        # workplace to eventually strip from location
        self.basedir: t.Optional[Path] = basedir

        # store mapping between filenames and their raw contents and function AST node
        self.parsed_symbols: t.Dict[str, t.Tuple[Node, bytes]] = {}

        # cache if top level call
        self.is_top_level: bool = False

    def __str__(self) -> str:
        return "tree-sitter"

    def run(self) -> Fuzzability:
        """
        This runs on two passes:

            - an initial run to parse and map every single function AST object
            from the source codebase to their appropriate files
            - the actual run to conduct static analysis on each function's AST
        """

        # first collect ASTs for every function
        log.info("Collecting and parsing ASTs for each function call")
        for filename in self.target:
            self._parse_symbols(filename)

        # now analyze each function_definition node
        log.info("Statically analyzing and calculating fuzzability for each call")
        for filename, entry in self.parsed_symbols.items():
            nodes = entry[0]
            contents = entry[1]
            for node in nodes:
                path = f"{filename}:{node.start_point[0]}"

                log.debug(
                    f"Attempting to capture function symbol name for the current node AST at {path}"
                )
                query = self.language.query(
                    """
                (identifier) @capture
                """
                )

                # TODO make this query better, match more specifically
                try:
                    identifier = query.captures(node)[0][0]
                    name = contents[identifier.start_byte : identifier.end_byte].decode(
                        "utf8"
                    )
                except Exception as err:
                    log.warning(
                        f"Parsing failed for {node} in {filename}, reason: {err}"
                    )
                    self.skipped[name] = path
                    continue

                if name in self.visited:
                    log.debug(f"{node} - already analyzed previously")
                    continue
                self.visited += [name]

                log.debug(f"Checking if we should ignore {name}")
                if self.skip_analysis(name):
                    self.skipped[name] = path
                    log.warning(f"Skipping {name} from fuzzability analysis.")
                    continue

                log.debug(f"Checking if {name} is a top-level call")
                self.is_top_level = self.is_toplevel_call(name, node)
                if not self.include_nontop and not self.is_top_level:
                    log.warning(
                        f"Skipping {name} (not top-level) from fuzzability analysis."
                    )
                    self.skipped[name] = path
                    continue

                log.info(f"Starting analysis for function {name}")
                self.scores += [self.analyze_call(name, node, filename, contents)]

        return super()._rank_fuzzability(self.scores)

    def _parse_symbols(self, filename: Path) -> None:
        """Helper to recover all function implementations from a source target"""

        # fix up path if a basedir is present
        if self.basedir:
            filepath = filename.relative_to(self.basedir)
        else:
            filepath = filename

        # ignore all unit tests (TODO: enable)
        if "test" in str(filepath).lower():
            log.info(f"{filepath} - skipping as it's a potential unit test file")
            return None

        # switch over language if different language detected
        extension = filepath.suffix
        if extension in SOURCE_FILE_EXTS[1:]:
            self.language = Language(BUILD_PATH, "cpp")
        else:
            self.language = Language(BUILD_PATH, "c")

        self.parser.set_language(self.language)

        with open(filename, "rb") as source_file:
            contents = source_file.read()

        tree = self.parser.parse(contents)
        # log.debug(tree.root_node.sexp())

        log.debug(f"Grabbing function definitions in {filepath}")
        query = self.language.query(
            """
        (function_definition) @capture
        """
        )

        log.debug(f"Aggregating definition captures in {filepath}")

        # store function definition mappings for the file
        captures = [node for (node, _) in query.captures(tree.root_node)]
        self.parsed_symbols[filepath] = (captures, contents)

    def analyze_call(
        self, name: str, func: Node, filename: str, contents: bytes
    ) -> CallScore:
        return CallScore(
            name=name,
            loc=f"{filename}:{func.start_point[0]}",
            toplevel=self.is_top_level,
            fuzz_friendly=self.is_fuzz_friendly(name),
            risky_sinks=self.risky_sinks(func, contents),
            natural_loops=self.natural_loops(func),
            coverage_depth=self.get_coverage_depth(func),
            cyclomatic_complexity=self.get_cyclomatic_complexity(func),
            stripped=False,
        )

    def skip_analysis(self, name: str) -> bool:
        """Handles parsing edge cases that yield weird function nodes"""
        if super().skip_analysis(name):
            return True

        # name parsed is primitive type, skip
        if name in ["void", "int", "char"]:
            return True

        # TODO: might be type, make this check better tho
        if name.isupper() or name.endswith("_t") or "*" in name:
            return True

        return False

    def is_toplevel_call(self, name: str, node: Node) -> bool:
        """
        Function implementation should not be static, and has no parent
        callers.
        """

        # ignore if static function
        # TODO: deal with other edge cases and potential macro aliases
        if node.children[0].type == "storage_class_specifier":
            return False

        # get call_expressions for each function name
        for _, entry in self.parsed_symbols.items():
            nodes = entry[0]
            contents = entry[1]
            for node in nodes:
                query = self.language.query(
                    """
                (call_expression) @capture
                """
                )

                # get captured nodes and retrieve name for calls, determine if our current
                # target is a top-level call
                captures = [n for (n, _) in query.captures(node)]
                for capture in captures:
                    call_name = contents[capture.start_byte : capture.end_byte].decode(
                        "utf8"
                    )
                    if call_name == name:
                        return False

        return True

    def risky_sinks(self, func: Node, contents: bytes) -> int:
        """
        Parse the parameter list of the function AST, grab the callees, and
        check to see if the parameters flow into risky callees.

        TODO: this dataflow analysis is quite rudimentary and doesn't account
        for reassignments
        """
        log.debug(f"{func} - checking for risky sinks")

        # number of times an argument flows into a risky call
        instances = 0

        # grab the parameter list and parse the parameters on our own,
        # ignore if we don't have any parameters
        query = self.language.query(
            """
        (parameter_list) @capture
        """
        )
        captures = query.captures(func)
        if len(captures) == 0:
            return instances

        capture = [n for (n, _) in captures][0]
        param_list = contents[capture.start_byte + 1 : capture.end_byte - 1].decode(
            "utf8"
        )

        # recover only the param name
        # TODO: include types and make this better
        params = param_list.split(", ")

        # TODO: deal with no-name arguments betters
        try:
            params = [p.split(" ")[1].replace("*", "") for p in params]
        except IndexError:
            log.warning(
                f"{func} - cannot get risky sinks because fuzzable cannot parse the parameters"
            )
            return instances

        # TODO: should we add a configuration knob that supports just checking
        # for risky calls even if no arguments flow through them?
        if len(params) == 0:
            return instances

        # now get all callees in the function and check if parameters flow into them
        query = self.language.query(
            """
        (call_expression) @capture
        """
        )
        captures = [n for (n, _) in query.captures(func)]
        for callee in captures:
            call_name = contents[callee.start_byte : callee.end_byte].decode("utf8")
            if not AstAnalysis._is_risky_call(call_name):
                continue

            # grab and parse the argument list
            query = self.language.query(
                """
            (argument_list) @capture
            """
            )
            capture = [n for (n, _) in query.captures(callee)][0]
            arg_list = contents[capture.start_byte + 1 : capture.end_byte - 1].decode(
                "utf8"
            )
            args = arg_list.split(", ")

            # this should be unreachable
            if len(args) == 0:
                continue

            param_flows_to_arg = all(item in args for item in params)
            if param_flows_to_arg:
                instances += 1

        return instances

    def get_coverage_depth(self, func: Node) -> int:
        """
        TODO: make this traverse
        """
        log.debug(f"{func} - getting callgraph depth")
        call_query = self.language.query(
            """
        (call_expression) @capture
        """
        )
        return len([n for (n, _) in call_query.captures(func)])

    def natural_loops(self, func: Node) -> int:
        log.debug(f"{func} - getting number of natural loops")
        looping_nodes = [
            "do_statement",
            "for_range_loop",
            "for_statement",
            "while_statement",
        ]
        return self._visit_node(func, looping_nodes)

    def get_cyclomatic_complexity(self, func: Node) -> int:
        """
        M = E − N + 2P
        """
        log.debug(f"{func} - getting cyclomatic complexity")
        branching_nodes = [
            "if_statement",
            "case_statement",
            "do_statement",
            "for_range_loop",
            "for_statement",
            "goto_statement",
            "function_declarator",
            "pointer_declarator",
            "struct_specifier",
            "preproc_elif",
            "while_statement",
            "switch_statement",
            "&&",
            "||",
        ]
        return self._visit_node(func, branching_nodes)

    def _visit_node(self, node: Node, checklist: t.List[str]) -> int:
        count = 0
        if node.type in checklist:
            count += 1
        for child in node.children:
            count += self._visit_node(child, checklist)
        return count
