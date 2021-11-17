"""
analysis.py

    Implements object that interfaces fuzzability analysis and score calculation
    for a given function from a binary view.
"""
import typing as t

import binaryninja.log as log
from binaryninja.settings import Settings

# interesting patterns to parse for in unstripped symbols when determining fuzzability
INTERESTING_PATTERNS = ["Parse", "Read", "Buf", "File", "Input", "String"]


class FuzzableAnalysis:
    """
    Wraps and handles analysis of a single valid function from a binary view,
    calculating a fuzzability score based on varying metrics, and outputs a
    markdown row for final table output.
    """

    def __init__(self, target):
        # parse basic function identifying info
        self.name = target.name
        log.log_info(f"Starting analysis for: function: {self.name}")

        # analyze function name properties
        self.stripped = "sub_" in self.name
        self.interesting_name = False
        if not self.stripped:
            self.interesting_name = any(
                [
                    pattern in self.name or pattern.lower() in self.name
                    for pattern in INTERESTING_PATTERNS
                ]
            )

        # analyze function arguments for fuzzable patterns
        self.args = target.parameter_vars
        self.interesting_args = False
        for arg in self.args:
            if arg.type == "char*":
                self.interesting_args = True
                break

        # a higher depth means more code coverage for the fuzzer, makes function more viable for testing
        # recursive calls to self mean higher cyclomatic complexity, also increases viability for testing
        (
            self.depth,
            self.recursive,
            self.visited,
        ) = FuzzableAnalysis.get_callgraph_complexity(target)

        # natural loop / iteration detected is often good behavior for a fuzzer to test, such as walking/scanning over
        # input data (aka might be a good place to find off-by-ones). Does not account for any type of basic-block obfuscation.
        self.has_loop = FuzzableAnalysis.contains_loop(target)

    def markdown_row(self):
        """Output as a Markdown row when displaying back to user"""
        return f"| [{self.name}](binaryninja://?expr={self.name}) | {self.fuzzability} | {self.depth} | {self.has_loop} | {self.recursive} | \n"

    def csv_row(self):
        """Generate a CSV row for exporting to file"""
        return f"{self.name}, {self.stripped}, {self.interesting_name}, {self.interesting_args}, {self.depth}, {self.has_loop}, {self.fuzzability}\n"

    @staticmethod
    def get_callgraph_complexity(target) -> (int, bool, t.List[str]):
        """
        Calculates coverage depth by doing a depth first search on function call graph,
        return a final depth and flag denoting recursive implementation
        """

        depth = 0
        recursive = False

        # stores only the name of the symbol we've already visited, is less expensive
        visited = []

        # as we iterate over callees, add to a callstack and iterate over callees
        # for those as well, adding to the callgraph until we're done with all
        callstack = [target]
        while callstack:

            # increase depth as we finish iterating over callees for another func
            func = callstack.pop()
            depth += 1

            # add all childs to callgraph, and add those we haven't recursed into callstack
            for child in func.callees:
                if child.name not in visited:
                    callstack += [child]

                # set flag if function makes call at some point back to current target,
                # increment cycle if recursive child is primary target itself,
                # meaning, there is recursion involved.
                elif child.name == target.name:
                    recursive = True

            visited += [func.name]

        return (depth, recursive, visited)

    @staticmethod
    def contains_loop(target) -> bool:
        """
        Detection of loops is at a basic block level by checking the dominance frontier,
        which denotes the next successor the current block node will definitely reach. If the
        same basic block exists in the dominance frontier set, then that means the block will
        loop back to itself at some point in execution.
        """

        # iterate over each basic block and see if it eventually loops back to self
        for bb in target.basic_blocks:
            if bb in bb.dominance_frontier:
                return True

        return False

    @property
    def fuzzability(self) -> float:
        """
        Calculate a final fuzzability score once analysis is completed.
        """

        score = 0.0

        # function is publicly exposed
        if not self.stripped:
            score += 1.0

            # name contains interesting patterns often useful for fuzz harnesses
            if self.interesting_name:
                score += 1.0

        # function signature can directly consume fuzzer input
        if self.interesting_args:
            score += 1.0

        # function achieved an optimal threshold of coverage to be fuzzed
        depth_threshold = int(Settings().get_string("fuzzable.depth_threshold"))
        if self.depth >= depth_threshold:
            score += 1.0

        # contains loop won't change score if configured
        loop_increase = Settings().get_bool("fuzzable.loop_increase_score")
        if not loop_increase and self.has_loop:
            score += 1.0

        # auxiliary: recursive call doesn't change score, but useful information
        return score
