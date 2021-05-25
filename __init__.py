#!/usr/bin/env python3
"""
fuzzable.py

    Binary Ninja helper plugin for fuzzable target discovery.
"""
from binaryninja import *
from .functions import functions

# interesting patterns to parse for in unstripped symbols when determining fuzzability
INTERESTING_PATTERNS = ["Parse", "Read", "Buf", "File", "Input", "String"]

# imported names of common functions, including glibc calls to ignore
# TODO: determine based on executable format in current view
COMMON_FUNCS = functions.keys()

# configurable settings to tune
Settings().register_group("fuzzable", "Fuzzable")
Settings().register_setting(
    "fuzzable.depth_threshold",
    """
    {
        "title"         : "Callgraph depth threshold",
        "description"   : "Minimum number of levels in callgraph to be considered optimal for fuzzing.",
        "type"          : "string",
        "default"       : "100"
    }
""",
)

Settings().register_setting(
    "fuzzable.cycle_threshold",
    """
    {
        "title"         : "Callgraph recursive cycle threshold",
        "description"   : "Minimum number of recursive cycles in a given function call graph to be considered optimal for fuzzing.",
        "type"          : "string",
        "default"       : "10"
    }
""",
)


Settings().register_setting(
    "fuzzable.skip_stripped",
    """
    {
        "title"         : "Skip stripped functions for analysis",
        "description"   : "Turn on if stripped functions are abundant and costly to analyze.",
        "type"          : "boolean",
        "default"       : false
    }
""",
)


class FuzzableAnalysis:
    """
    Wraps and handles analysis of a single valid function from a binary view,
    calculating a fuzzability score based on varying metrics, and outputs a
    markdown row for final table output.
    """

    def __init__(self, target):
        # parse basic function identifying info
        self.name = target.name
        log_info(f"Starting analysis for: function: {self.name}")

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

        # FIXME: function signature can directly consume fuzzer input
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


class WrapperTask(BackgroundTaskThread):
    def __init__(self, view):
        super(WrapperTask, self).__init__(
            "Finding fuzzable targets in current binary view"
        )
        self.view = view

    def run(self):
        funcs = self.view.functions
        log_info(f"Starting target discovery against {len(funcs)} functions")

        # final markdown table to be presented to user, with headers created first
        markdown_result = "# Fuzzable Targets\n | Function Name | Fuzzability | Coverage Depth | Detected Cycles |\n| :--- | :--- | :--- | :--- |\n"

        # append to CSV buffer if user chooses to export after analysis
        csv_out = '"Name", "Stripped", "Interesting Name", "Interesting Args", "Depth", "Cycles", "Fuzzability"\n'

        # stores all parsed analysis objects
        parsed = []

        # iterate over each symbol
        for func in funcs:
            name = func.name

            # ignore common functions from other known libraries
            if any([pattern == name for pattern in COMMON_FUNCS]):
                log_info(f"Skipping analysis for known function {name}")
                continue

            # ignore targets with patterns that denote some type of profiling instrumentation, ie stack canary
            if name.startswith("_"):
                log_info(f"Skipping analysis for function {name}")
                continue

            # if set, ignore all stripped functions for faster analysis
            if ("sub_" in name) and Settings().get_bool("fuzzable.skip_stripped"):
                log_info(f"Skipping analysis for stripped function {name}")
                continue

            # instantiate module and add to parsed list
            analysis = FuzzableAnalysis(func)
            parsed += [analysis]

        # sort parsed by highest fuzzability score
        parsed = sorted(parsed, key=lambda x: x.fuzzability, reverse=True)

        # TODO sort again but by depth and cycles

        # add ranked results as rows to final markdown table and CSV if user chooses to export
        for analysis in parsed:
            markdown_result += analysis.markdown_row()
            csv_out += analysis.csv_row()

        self.view.store_metadata("csv", csv_out)

        # output report back to user
        show_markdown_report("Fuzzable targets", markdown_result)


def run_fuzzable(view):
    """ Callback used to instantiate thread and start analysis """
    task = WrapperTask(view)
    task.start()


def run_export_report(view):
    """ Generate a report from a previous analysis, and export as CSV """
    log_info("Attempting to export results to CSV")
    try:
        csv_output = view.query_metadata("csv")
    except KeyError:
        show_message_box("Error", "Cannot export without running an analysis first.")
        return

    # write last analysis to filepath
    csv_file = get_save_filename_input("Filename to export as CSV?", "csv")
    csv_file = csv_file.decode("utf-8") + ".csv"

    log_info(f"Writing to filepath {csv_file}")
    with open(csv_file, "w+") as fd:
        fd.write(csv_output)

    show_message_box("Success", f"Done, exported to {csv_file}")


PluginCommand.register(
    "Fuzzable\\Analyze fuzzable targets",
    "Identify and generate targets for fuzzing",
    run_fuzzable,
)

PluginCommand.register(
    "Fuzzable\\Export fuzzability report as CSV",
    "Identify and generate targets for fuzzing",
    run_export_report,
)
