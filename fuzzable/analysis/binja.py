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
from binaryninja.function import Function
from binaryninja.enums import LowLevelILOperation, SymbolType
from binaryninja.settings import Settings
from binaryninja.plugin import BackgroundTaskThread

from . import AnalysisBackend, AnalysisMode, Fuzzability
from ..metrics import CallScore, CoverageReport


class _BinjaAnalysisMeta(type(AnalysisBackend), type(BackgroundTaskThread)):
    pass


class BinjaAnalysis(
    AnalysisBackend, BackgroundTaskThread, metaclass=_BinjaAnalysisMeta
):
    """Derived class to support Binary Ninja, and can be dispatched as a task from the plugin."""

    def __init__(self, target: BinaryView, mode: AnalysisMode, headless: bool = False):
        AnalysisBackend.__init__(self, target, mode)
        BackgroundTaskThread.__init__(
            self, "Finding fuzzable targets in current binary view"
        )
        self.view = target
        self.headless = headless

    def __str__(self) -> str:
        return "Binary Ninja"

    def run(self) -> t.Optional[Fuzzability]:
        funcs = self.view.functions

        log.log_info(f"Starting fuzzable analysis over {len(funcs)} symbols in binary")
        for func in funcs:
            name = func.name

            log.log_debug("Checking to see if we should ignore")
            if self.skip_analysis(func):
                continue

            # if recommend mode, filter and run only those that are top-level
            if self.mode == AnalysisMode.RECOMMEND and not self.is_toplevel_call(func):
                continue

            log.log_info(f"Starting analysis for function {name}")
            score = self.analyze_call(name, func)

            # if a loop is detected in the target, and it exists as part a callgraph,
            # set has_loop for that parent as well
            """
            for prev in analyzed:
                if score.has_loop and score.name in prev.visited:
                    prev.has_loop = True
            """

            # TODO: more filtering with RECOMMEND
            self.scores += [score]

        log.log_info("Done, ranking the analyzed calls for reporting")
        ranked = super()._rank_fuzzability(self.scores)

        # if headless, handle displaying results back
        if not self.headless:
            csv_result = '"Name", "Stripped", "Interesting Name", "Interesting Args", "Depth", "Cycles", "Fuzzability"\n'
            markdown_result = "# Fuzzable Targets\n | Function Name | Fuzzability | Coverage Depth | Has Loop? | Recursive Func? |\n| :--- | :--- | :--- | :--- |\n"
            for score in self.scores:
                markdown_result += score.table_row
                csv_result += score.csv_row

            log.log_info("Saving to memory and displaying finalized results...")
            self.view.store_metadata("csv", csv_result)
            self.view.show_markdown_report("Fuzzable targets", markdown_result)
            return None

        return ranked

    def analyze_call(self, name: str, func: Function) -> CallScore:
        stripped = "sub_" in name

        # no need to check if no name available
        # TODO: maybe we should run this if a signature was recovered
        fuzz_friendly = False
        if not stripped:
            fuzz_friendly = BinjaAnalysis.is_fuzz_friendly(name)

        return CallScore(
            name=name,
            toplevel=self.is_toplevel_call(func),
            fuzz_friendly=fuzz_friendly,
            risky_sinks=self.risky_sinks(func),
            contains_loop=BinjaAnalysis.contains_loop(func),
            coverage_depth=self.get_coverage_depth(func),
            stripped=stripped,
        )

    def skip_analysis(self, func: Function) -> bool:
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

    def is_toplevel_call(self, target: Function) -> bool:
        return len(target.callers) == 0

    def risky_sinks(self, func: Function) -> int:
        """
        For each parameter in the function, determine if it flows into a known risky
        function call.
        """

        risky_sinks = 0

        # visit all other calls with depth-first search until we reach a risky sink
        callstack = [func]
        while callstack:
            func = callstack.pop()

            # Iterate over each argument and check for taint sinks
            for arg in func.parameter_vars:
                arg_refs = func.get_hlil_var_refs(arg)

                log.log_debug(f"{func.name}: {arg_refs}")
                for ref in arg_refs:
                    insn = ref.arch.get_instruction_low_level_il_instruction(
                        self.view, ref.address
                    )

                    log.log_debug(f"{insn} - {insn.operation}")

                    # if call instruction, check out for risky pattern
                    if insn.operation in [
                        LowLevelILOperation.LLIL_CALL,
                        LowLevelILOperation.LLIL_JUMP,
                    ]:
                        callee = self.view.get_function_at(int(insn.dest))
                        call = callee.name

                        # TODO: should we traverse further if not a imported func
                        if BinjaAnalysis._is_risky_call(call):
                            risky_sinks += 1

                        # otherwise add to callstack and continue to trace arguments
                        elif (call is SymbolType.ImportedFunctionSymbol) or (
                            call is SymbolType.LibraryFunctionSymbol
                        ):
                            callstack += [callee]

        return risky_sinks

    def get_coverage_depth(self, target: Function) -> int:
        """
        Calculates coverage depth by doing a depth first search on function call graph,
        and return a final depth and flag denoting recursive implementation
        """

        depth = 0

        # as we iterate over callees, add to a callstack and iterate over callees
        # for those as well, adding to the callgraph until we're done with all
        callstack = [target]
        while callstack:

            # increase depth as we finish iterating over callees for another func
            func = callstack.pop()
            depth += 1

            # add all childs to callgraph, and add those we haven't recursed into callstack
            for child in func.callees:
                if child.name not in self.visited:
                    callstack += [child]

            self.visited += [func.name]

        return depth

    @staticmethod
    def contains_loop(target: Function) -> bool:
        return any([bb in bb.dominance_frontier for bb in target.basic_blocks])

    def get_cyclomatic_complexity(self) -> int:
        """
        HEURISTIC

        M = E − N + 2P
        """
        pass


def run_fuzzable_recommend(view) -> None:
    task = BinjaAnalysis(view, AnalysisMode.RECOMMEND)
    task.start()


def run_fuzzable_rank(view) -> None:
    task = BinjaAnalysis(view, AnalysisMode.RANK)
    task.start()


def run_export_csv(view: BinaryView) -> None:
    """Generate a CSV report from a previous analysis"""
    log.log_info("Attempting to export results to CSV")
    try:
        csv_output = view.query_metadata("csv")
    except KeyError:
        interaction.show_message_box(
            "Error", "Cannot export without running an analysis first."
        )
        return

    csv_file = interaction.get_save_filename_input("Filename to export as CSV?", "csv")
    csv_file = csv_file.decode("utf-8") + ".csv"

    log.log_info(f"Writing to filepath {csv_file}")
    with open(csv_file, "w+") as fd:
        fd.write(csv_output)

    interaction.show_message_box("Success", f"Done, exported to {csv_file}")


def run_export_md(view: BinaryView) -> None:
    """Generate a markdown report from a previous analysis"""
    log.log_info("Attempting to export results to markdown")
    try:
        markdown_output = view.query_metadata("md")
    except KeyError:
        interaction.show_message_box(
            "Error", "Cannot export without running an analysis first."
        )
        return

    # TODO


def run_harness_generation(view, func) -> None:
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
