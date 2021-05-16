#!/usr/bin/env python3
"""
fuzzable.py
"""
from binaryninja import *

# interesting patterns to parse for in unstripped symbols when determining fuzzability
INTERESTING_PATTERNS = [
    "Parse", "Read", "Buf", "Get", "File", "Input",
]

class CallGraph(BackgroundTaskThread):
    def __init__(self, root):
        super(CallGraph, self).__init__(f"Creating callgraph for function {root.name}")

        # parse basic function identifying info
        self.name = root.name
        self.args = root.parameter_vars
        #log_info(f"Analyzing {self.name} {str(self.args)}")

        # given an unstripped symbol check if any interesting patterns are present
        self.stripped = "sub_" in self.name
        self.takes_fuzzable_in = False
        if not self.stripped:
            pass

        # more depth represents maximizing code coverage when fuzzing
        self.depth = 0

    def __str__(self):
        """ Output as a Markdown row when displaying back to user """
        return "test\t\t|\t\ttest"


    def gen_graph(self):
        pass

    def calculate_score(self):
        score = 0



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

    # final markdown table to be presented to user
    markdown_result = """
    | Function Name | Fuzzable? |
    -----------------------------
    """
    
    # iterate over each symbol
    for func in funcs:

        # ignore executable constructor and destructor
        if func.name == "_init" or func.name == "_fini":
            continue

        callgraph = CallGraph(func)

    show_plain_text_report("Fuzzable targets", markdown_result)


PluginCommand.register(
    "Find fuzzable targets",
    "Identify and generate targets for fuzzing",
    fuzzable
)

PluginCommand.register_for_function(
    "Generate a fuzzable score",
    "Given a function, get a fuzzability score",
    get_fuzzable_score
)
