"""
analysis.py

    Implements object that interfaces fuzzability analysis and score calculation
    for a given function from a binary view.
"""

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
        (self.depth, self.recursive) = FuzzableAnalysis.get_callgraph_complexity(target)

        # natural loop / iteration detected is often good behavior for a fuzzer to test, such as walking/scanning over
        # input data (aka might be a good place to find off-by-ones). Does not account for any type of basic-block obfuscation.
        self.cycles = FuzzableAnalysis.get_cycle_complexity(target)

    def markdown_row(self):
        """ Output as a Markdown row when displaying back to user """
        return f"| [{self.name}](binaryninja://?expr={self.name}) | {self.fuzzability} | {self.depth} | {self.recursive} |\n"

    def csv_row(self):
        """ Generate a CSV row for exporting to file """
        return f"{self.name}, {self.stripped}, {self.interesting_name}, {self.interesting_args}, {self.depth}, {self.cycles}, {self.fuzzability}\n"

    @staticmethod
    def get_callgraph_complexity(target) -> (int, bool):
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

        return (depth, recursive)

    @staticmethod
    def get_cycle_complexity(target):
        """
        Helper that does iterative loop detection by doing same depth-first search, but instead
        at a basic-block level.
        """

        cycles = 0
        visited = []

        # get the root basic block of the target
        bb_root = list(target.basic_blocks)[0]

        """
        # like callgraph, store stack for depth-first-search
        callstack = [bb_root]
        while callstack:

            # get next block
            bb = callstack.pop()

            # start iterating over outer leftmost edges
            for child in bb.outgoing_edges:
                print(type(child.target))
                if child not in visited:
                    callstack += [child.target]
                else:
                    cycles += 1
            
            visited += [bb]
        """

        return cycles

    @property
    def fuzzability(self) -> float:
        """ 
        Calculate a final fuzzability score once analysis is completed.
        """

        score = 0.0

        # function is publicly exposed
        if not self.stripped:
            score += 1

            # name contains interesting patterns often useful for fuzz harnesses
            if self.interesting_name:
                score += 1

        # function signature can directly consume fuzzer input
        if self.interesting_args:
            score += 1

        # function achieved an optimal threshold of coverage to be fuzzed
        depth_threshold = int(Settings().get_string("fuzzable.depth_threshold"))
        if self.depth >= depth_threshold:
            score += 1

        # function demonstrated high level of cyclic complexity, optimal for fuzzing
        cycles_threshold = int(Settings().get_string("fuzzable.cycle_threshold"))
        if self.cycles >= cycles_threshold:
            score += 1

        """
        # auxiliary: recursive call to self increases score not as much
        if self.recursive:
            score += 0.5
        """

        return score
