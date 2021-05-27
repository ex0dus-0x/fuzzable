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
        (self.depth, self.cycles) = FuzzableAnalysis.get_callgraph_complexity(target)

    def markdown_row(self):
        """ Output as a Markdown row when displaying back to user """
        return f"| [{self.name}](binaryninja://?expr={self.name}) | {self.fuzzability} | {self.depth} | {self.cycles} |\n"

    def csv_row(self):
        """ Generate a CSV row for exporting to file """
        return f"{self.name}, {self.stripped}, {self.interesting_name}, {self.interesting_args}, {self.depth}, {self.cycles}, {self.fuzzability}\n"

    @staticmethod
    def get_callgraph_complexity(target):
        """ Helper that recurses the callgraph and calculates its depth and cyclomatic complexity """

        depth = 0
        cycles = 0

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

                # increment cycle if recursive child is primary target itself,
                # not another subroutine within the callgraph
                elif child.name == target.name:
                    cycles += 1

            visited += [func.name]

        return (depth, cycles)

    @property
    def fuzzability(self):
        """
        Calculate a final fuzzability score once analysis is completed.
        """
        score = 0

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

        """ 
        TODO: more testing to determine if metric should be incorporated
        if self.cycles >= cycles_threshold:
            score += 1
        """

        return score
