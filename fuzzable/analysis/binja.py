"""
binja.py

    Implements object that interfaces fuzzability analysis and score calculation
    for a given function from a binary view.
"""
import os
import typing as t

import binaryninja
import binaryninja.log as log
import binaryninja.interaction as interaction

from binaryninja.enums import SymbolType
from binaryninja.settings import Settings
from binaryninja.plugin import BackgroundTaskThread

from . import INTERESTING_PATTERNS


class WrapperTask(BackgroundTaskThread):
    def __init__(self, view):
        super(WrapperTask, self).__init__(
            "Finding fuzzable targets in current binary view"
        )
        self.view = view

    def run(self):
        funcs = self.view.functions
        log.log_info(f"Starting target discovery against {len(funcs)} functions")

        # final markdown table to be presented to user, with headers created first
        markdown_result = "# Fuzzable Targets\n | Function Name | Fuzzability | Coverage Depth | Has Loop? | Recursive Func? |\n| :--- | :--- | :--- | :--- |\n"

        # append to CSV buffer if user chooses to export after analysis
        csv_out = '"Name", "Stripped", "Interesting Name", "Interesting Args", "Depth", "Cycles", "Fuzzability"\n'

        # stores all parsed analysis objects
        parsed = []

        # iterate over each symbol
        for func in funcs:
            name = func.name
            symbol = func.symbol.type

            # ignore imported functions from other libraries, ie glibc or win32api
            if (symbol is SymbolType.ImportedFunctionSymbol) or (
                symbol is SymbolType.LibraryFunctionSymbol
            ):
                log.log_info(f"Skipping analysis for known function {name}")
                continue

            # ignore targets with patterns that denote some type of profiling instrumentation, ie stack canary
            if name.startswith("_"):
                log.log_info(f"Skipping analysis for function {name}")
                continue

            # if set, ignore all stripped functions for faster analysis
            if ("sub_" in name) and Settings().get_bool("fuzzable.skip_stripped"):
                log.log_info(f"Skipping analysis for stripped function {name}")
                continue

            # instantiate analysis of the given target
            analysis = FuzzableAnalysis(func)

            # if a loop is detected in the target, and it exists as part a callgraph,
            # set has_loop for that parent as well
            # TODO: cleanup and encapsulate in FuzzableAnalysis
            for prev in parsed:
                if analysis.has_loop and analysis.name in prev.visited:
                    prev.has_loop = True

            parsed += [analysis]

        # sort parsed by highest fuzzability score and coverage depth
        parsed = sorted(parsed, key=lambda x: (x.fuzzability, x.depth), reverse=True)

        # add ranked results as rows to final markdown table and CSV if user chooses to export
        for analysis in parsed:
            markdown_result += analysis.markdown_row()
            csv_out += analysis.csv_row()

        # store CSV output to memory
        self.view.store_metadata("csv", csv_out)

        # output report back to user
        self.view.show_markdown_report("Fuzzable targets", markdown_result)


def run_fuzzable(view):
    """Callback used to instantiate thread and start analysis"""
    task = WrapperTask(view)
    task.start()


def run_export_report(view):
    """Generate a report from a previous analysis, and export as CSV"""
    log.log_info("Attempting to export results to CSV")
    try:
        csv_output = view.query_metadata("csv")
    except KeyError:
        interaction.show_message_box(
            "Error", "Cannot export without running an analysis first."
        )
        return

    # write last analysis to filepath
    csv_file = interaction.get_save_filename_input("Filename to export as CSV?", "csv")
    csv_file = csv_file.decode("utf-8") + ".csv"

    log.log_info(f"Writing to filepath {csv_file}")
    with open(csv_file, "w+") as fd:
        fd.write(csv_output)

    interaction.show_message_box("Success", f"Done, exported to {csv_file}")


def run_harness_generation(view, func):
    """Experimental automatic fuzzer harness generation support"""

    template_file = os.path.join(binaryninja.user_plugin_path(), "fuzzable")
    if view.view_type == "ELF":
        template_file += "/templates/linux.cpp"
    else:
        interaction.show_message_box(
            "Error",
            "Experimental harness generation is only supported for ELFs at the moment",
        )
        return

    # parse out template based on executable format, and start replacing
    with open(template_file, "r") as fd:
        template = fd.read()

    log.log_info("Replacing elements in template")
    template = template.replace("{NAME}", func.name)
    template = template.replace("{RET_TYPE}", str(func.return_type))

    harness = interaction.get_save_filename_input("Filename to write to?", "cpp")
    harness = harness.decode("utf-8") + ".cpp"

    log.log_info("Writing new template to workspace")
    with open(harness, "w+") as fd:
        fd.write(template)

    interaction.show_message_box("Success", f"Done, wrote fuzzer harness to {harness}")


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
