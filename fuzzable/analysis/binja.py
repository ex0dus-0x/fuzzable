"""
binja.py

    Fuzzable analysis support for the Binary Ninja disassembler.
    Can be invoked both through registered plugin handlers, and through
    a headless standalone CLI.

"""
import os
import typing as t

import binaryninja
import binaryninja.log as log
import binaryninja.interaction as interaction

from binaryninja import BinaryView
from binaryninja.enums import SymbolType
from binaryninja.settings import Settings
from binaryninja.plugin import BackgroundTaskThread

from fuzzable.analysis import AnalysisBackend, AnalysisMode
from fuzzable.metrics import CallScore, CoverageReport


class BinjaAnalysis(AnalysisBackend, BackgroundTaskThread):
    """Derived class to support Binary Ninja, and can be dispatched as a task from the plugin."""

    def __init__(self, target):
        super(BinjaAnalysis, self).__init__(
            "Finding fuzzable targets in current binary view"
        )
        self.view: BinaryView = target

    def __str__(self) -> str:
        return "Binary Ninja"

    def run(self, headless: bool = False) -> None:
        funcs = self.view.functions

        analyzed = []
        log.log_info(f"Starting fuzzable analysis over {len(funcs)} symbols in binary")
        for func in funcs:
            name = func.name

            log.log_trace("Checking to see if we should ignore")
            if BinjaAnalysis.ignore(func):
                continue

            # if recommend, filter and run only those that are top-level
            if (
                self.mode == AnalysisMode.RECOMMEND
                and not BinjaAnalysis.is_toplevel_call(func)
            ):
                continue

            log.log_info(f"Starting analysis for function {name}")
            score = self.analyze_call(name, func)

            # if a loop is detected in the target, and it exists as part a callgraph,
            # set has_loop for that parent as well
            for prev in analyzed:
                if score.has_loop and score.name in prev.visited:
                    prev.has_loop = True

            # TODO: more filtering with RECOMMEND
            analyzed += [score]

        # sort parsed by highest fuzzability score
        log.log_info("Done, ranking the analyzed calls for reporting")
        ranked = sorted(analyzed, key=lambda x: (x.fuzzability, x.depth), reverse=True)

        # TODO: fix
        if not headless:
            csv_result = '"Name", "Stripped", "Interesting Name", "Interesting Args", "Depth", "Cycles", "Fuzzability"\n'
            markdown_result = "# Fuzzable Targets\n | Function Name | Fuzzability | Coverage Depth | Has Loop? | Recursive Func? |\n| :--- | :--- | :--- | :--- |\n"
            for score in ranked:
                markdown_result += score.table_row
                csv_result += score.csv_row

            log.log_info("Saving to memory and displaying finalized results...")
            self.view.store_metadata("csv", csv_result)
            self.view.show_markdown_report("Fuzzable targets", markdown_result)
            return None

    def analyze_call(self, name: str, func: t.Any) -> CallScore:
        stripped = "sub_" in name

        # no need to check if no name available
        # TODO: maybe we should run this if a signature was recovered
        fuzz_friendly = False
        if not stripped:
            fuzz_friendly = BinjaAnalysis.is_fuzz_friendly(name)

        return CallScore(
            name=name,
            toplevel=BinjaAnalysis.is_toplevel_call(func),
            fuzz_friendly=fuzz_friendly,
            has_risky_sink=BinjaAnalysis.has_risky_sink(func),
            contains_loop=BinjaAnalysis.contains_loop(func),
            coverage_depth=BinjaAnalysis.get_coverage_depth(func),
            stripped=stripped,
        )

    @staticmethod
    def skip_analysis(func) -> bool:
        name = func.name
        symbol = func.symbol.type
        log.log_debug(f"{name} - {symbol}")

        # ignore imported functions from other libraries, ie glibc or win32api
        if (symbol is SymbolType.ImportedFunctionSymbol) or (
            symbol is SymbolType.LibraryFunctionSymbol
        ):
            log.log_debug(f"{name} is an import, skipping")
            return True

        # ignore targets with patterns that denote some type of profiling instrumentation, ie stack canary
        if name.startswith("_"):
            log.log_debug(f"{name} is instrumentation, skipping")
            return True

        # if set, ignore all stripped functions for faster analysis
        if ("sub_" in name) and Settings().get_bool("fuzzable.skip_stripped"):
            log.log_debug(f"{name} is stripped, skipping")
            return True

        return False

    @staticmethod
    def is_toplevel_call(target: t.Any) -> bool:
        return len(target.callers) == 0

    @staticmethod
    def has_risky_sink(self, func) -> bool:
        args = func.parameter_vars
        for arg in args:
            print(arg)

    @staticmethod
    def get_coverage_depth(target) -> CoverageReport:
        """
        Calculates coverage depth by doing a depth first search on function call graph,
        and return a final depth and flag denoting recursive implementation
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
        return any([bb in bb.dominance_frontier for bb in target.basic_blocks])


def run_fuzzable_recommend(view):
    task = BinjaAnalysis(view, AnalysisMode.RECOMMEND)
    task.start()


def run_fuzzable_rank(view):
    task = BinjaAnalysis(view, AnalysisMode.RANK)
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
        template_file += "/templates/linux_harness_template.cpp"
    else:
        interaction.show_message_box(
            "Error",
            "Experimental harness generation is only supported for ELFs at the moment",
        )
        return

    # parse out template based on executable format, and start replacing
    with open(template_file, "r") as fd:
        template = fd.read()

    log.log_debug("Generating harness from template")
    template = template.format(
        function_name=func.name,
        return_type=str(func.return_type),
        parameters=func.parameter_vars,
    )
    harness = interaction.get_save_filename_input("Filename to write to?", "cpp")
    harness = harness.decode("utf-8") + ".cpp"

    log.log_debug(f"Writing harness `{harness}` to workspace")
    with open(harness, "w+") as fd:
        fd.write(template)

    interaction.show_message_box("Success", f"Done, wrote fuzzer harness to {harness}")
