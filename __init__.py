#!/usr/bin/env python3
"""
fuzzable.py

    Binary Ninja helper plugin for fuzzable target discovery.
"""
from binaryninja import *

# if switched, will skip all analysis of stripped symbols
SKIP_STRIPPED = False

# how many callgraph levels to hit in order to meet coverage standard
DEPTH_THRESHOLD = 4

# interesting patterns to parse for in unstripped symbols when determining fuzzability
INTERESTING_PATTERNS = ["Parse", "Read", "Buf", "File", "Input", "String"]

# patterns to skip over and not care about
SKIP_PATTERNS = [
    # constructor and destructor
    "_init",
    "_fini",
    "_start",
    # standard library
    "__cxx",
    "gnu",
    # instrumentation
    "__afl",
    "__asan",
    "__hfuzz",
]

FUNCTION_SIGNATURES = [[]]


class FuzzableAnalysis(BackgroundTaskThread):
    def __init__(self, root):
        super(FuzzableAnalysis, self).__init__(
            f"Creating callgraph for function {root.name}"
        )

        # parse basic function identifying info
        self.name = root.name
        log_info(f"Starting analysis for: function: {self.name}")

        self.args = root.parameter_vars

        # analyze function name properties
        self.stripped = "sub_" in self.name
        if not self.stripped:
            self.interesting_name = any(
                [pattern in self.name for pattern in INTERESTING_PATTERNS]
            )

        #

        # more depth represents maximizing code coverage when fuzzing
        self.depth = 0

    def __str__(self):
        """ Output as a Markdown row when displaying back to user """
        return f"| {self.name} | {self.fuzzability} | {self.depth} | \n"

    @property
    def fuzzability(self):
        """
        Calculate a final fuzzability score once analysis is completed.
        """

        score = 0

        # function is publicly exposed
        if not self.stripped:
            score += 1

            # check if name contains interesting patterns
            if self.interesting_name:
                score += 1

        # function signature can directly consume fuzzer input

        # function achieved a high threshold of coverage
        if self.depth >= DEPTH_THRESHOLD:
            score += 1

        return score


def get_fuzzable_score(view, function):
    """
    Callback used to get an individual fuzzable score for a given function,
    """
    log_info("Getting a fuzzable score for function")
    log_info(function)


def fuzzable(view):
    """
    Main callback used to generate call graphs for symbols and determine fuzzable targets
    based on metrics gathered.
    """
    funcs = view.functions
    log_info(f"Starting target discovery against {len(funcs)} functions")

    # final markdown table to be presented to user, with headers created first
    markdown_result = (
        "| Function Name | Fuzzability | Coverage Depth | \n| :--- | :--- | :--- |\n"
    )

    # stores all parsed analysis objects
    parsed = []

    # iterate over each symbol
    for func in funcs:

        # ignore targets with certain patterns
        name = func.name
        if any([pattern in name for pattern in SKIP_PATTERNS]):
            log_info(f"Skipping analysis for function {name}")
            continue

        # if set, ignore all stripped functions for faster analysis
        if ("sub_" in name) and SKIP_STRIPPED:
            log_info(f"Skipping analysis for stripped function {name}")
            continue

        # instantiate module and add to parsed list
        analysis = FuzzableAnalysis(func)
        parsed += [analysis]

    # sort parsed by highest fuzzability score
    parsed = sorted(parsed, key=lambda x: x.fuzzability, reverse=True)

    # add ranked results as rows to final markdown table
    for analysis in parsed:
        markdown_result += str(analysis)
    show_markdown_report("Fuzzable targets", markdown_result)


PluginCommand.register(
    "Find fuzzable targets", "Identify and generate targets for fuzzing", fuzzable
)

PluginCommand.register_for_function(
    "Generate a fuzzable score",
    "Given a function, get a fuzzability score",
    get_fuzzable_score,
)
