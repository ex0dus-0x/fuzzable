"""
binja.py

    Fuzzable analysis support for the Binary Ninja disassembler.
    Can be invoked both through registered plugin handlers, and through
    a headless standalone CLI.

"""
import os
from symtable import Symbol
import typing as t

import binaryninja
import binaryninja.log as log
import binaryninja.interaction as interaction

from binaryninja import BinaryView
from binaryninja.function import Function
from binaryninja.lowlevelil import LowLevelILReg
from binaryninja.enums import LowLevelILOperation, SymbolType
from binaryninja.settings import Settings
from binaryninja.plugin import BackgroundTaskThread

from . import AnalysisBackend, AnalysisMode, Fuzzability
from ..metrics import CallScore
from ..cli import COLUMNS


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
        self.view: BinaryView = target
        self.headless: bool = headless

    def __str__(self) -> str:
        return "Binary Ninja"

    def run(self) -> t.Optional[Fuzzability]:
        funcs = self.view.functions

        log.log_info(f"Starting fuzzable analysis over {len(funcs)} symbols in binary")
        for func in funcs:
            name = func.name

            log.log_debug("Checking to see if we should ignore")
            if self.skip_analysis(func):
                self.skipped += 1
                continue

            # if recommend mode, filter and run only those that are top-level
            if self.mode == AnalysisMode.RECOMMEND and not self.is_toplevel_call(func):
                continue

            log.log_info(f"Starting analysis for function {name}")
            score = self.analyze_call(name, func)

            """
            # if a loop is detected in the target, and it exists as part a callgraph,
            # set has_loop for that parent as well
            for prev in self.scores:
                if score.natural_loops != 0 and score.name in prev.visited:
                    prev.natural_loops = True
            """

            # TODO: more filtering with RECOMMEND
            self.scores += [score]

        log.log_info("Done, ranking the analyzed calls for reporting")
        ranked = super()._rank_fuzzability(self.scores)

        # if headless, handle displaying results back
        if not self.headless:
            csv_result = '"name", "fuzz_friendly", "risky_sinks", "natural_loops", "cyc_complex", "cov_depth", "fuzzability"\n'
            csv_result = ", ".join([f'"{column}"' for column in COLUMNS])

            # TODO: reuse rich for markdown
            markdown_result = f"""# Fuzzable Targets

This is a generated report that ranks fuzzability of every parsed symbol that was recovered in this binary. If you feel that the results
are incomplete, wait for Binary Ninja's initial analysis to finalize and re-run this feature in the plugin.

__Number of Symbols Analyzed:__ {len(ranked)}

__Number of Symbols Skipped:__ {self.skipped}

__Top Fuzzing Contender:__ [{ranked[0].name}](binaryninja://?expr={ranked[0].name})

## Ranked Table (MODE = {self.mode.name})

| Function Signature | Fuzzability Score | Fuzz-Friendly Name | Risky Data Sinks | Natural Loops | Cyclomatic Complexity | Coverage Depth |
|--------------------|-------------------|--------------------|------------------|---------------|-----------------------|----------------|
"""

            for score in ranked:
                markdown_result += score.binja_markdown_row
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
        fuzz_friendly = 0
        if not stripped:
            fuzz_friendly = BinjaAnalysis.is_fuzz_friendly(name)

        return CallScore(
            name=name,
            toplevel=self.is_toplevel_call(func),
            fuzz_friendly=fuzz_friendly,
            risky_sinks=self.risky_sinks(func),
            natural_loops=self.natural_loops(func),
            coverage_depth=self.get_coverage_depth(func),
            cyclomatic_complexity=self.get_cyclomatic_complexity(func),
            stripped=stripped,
        )

    def skip_analysis(self, func: Function) -> bool:
        name = func.name
        symbol = func.symbol.type
        log.log_debug(f"{name} - {symbol}")

        # ignore imported functions from other libraries, ie glibc or win32api
        if symbol in [
            SymbolType.ImportedFunctionSymbol,
            SymbolType.LibraryFunctionSymbol,
            SymbolType.ExternalSymbol,
            SymbolType.ImportAddressSymbol,
            SymbolType.ImportedDataSymbol,
        ]:
            log.log_debug(f"{name} is an import, skipping")
            return True

        # ignore targets with patterns that denote some type of profiling instrumentation, ie stack canary
        if name.startswith("__"):
            log.log_debug(f"{name} is potentially instrumentation, skipping")
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

                        # TODO deal with registers with addrs
                        if isinstance(insn.dest, LowLevelILReg):
                            continue

                        try:
                            callee = self.view.get_function_at(int(insn.dest))
                            call = callee.name
                        except Exception:
                            continue

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
        and return a final depth and flag denoting recursive implementation.
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

    def natural_loops(self, target: Function) -> int:
        return len([bb in bb.dominance_frontier for bb in target.basic_blocks])

    def get_cyclomatic_complexity(self, func: Function) -> int:
        num_blocks = len(func.basic_blocks)
        num_edges = sum([len(b.outgoing_edges) for b in func.basic_blocks])
        return num_blocks - num_edges + 2


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

    md_file = interaction.get_save_filename_input("Filename to export as CSV?", "csv")
    md_file = md_file.decode("utf-8") + ".md"

    # parse out template based on executable format, and start replacing
    with open(md_file, "w+") as fd:
        fd.write(markdown_output)

    interaction.show_message_box("Success", f"Done, exported to {md_file}")


def run_harness_generation(view, func) -> None:
    """Experimental automatic fuzzer harness generation support"""

    log.log_debug("Reading closed-source template from codebase")
    target_name = view.file.filename.split(".")[0]
    template_file = os.path.join(
        binaryninja.user_plugin_path(),
        "fuzzable/templates/linux_closed_source_harness.cpp",
    )
    with open(template_file, "r") as fd:
        template = fd.read()

    params = [f"{param.type} {param.name}" for param in func.parameter_vars.vars]

    log.log_debug("Generating harness from template")
    template = template.replace("{NAME}", os.path.basename(target_name))
    template = template.replace("{function_name}", func.name)
    template = template.replace("{return_type}", str(func.return_type))
    template = template.replace("{type_args}", ", ".join(params))

    log.log_debug("Getting filename to write to")
    harness = f"{target_name}_{func.name}_harness.cpp"
    # harness = interaction.get_save_filename_input("Path to write to?", "cpp", default_name)
    # harness = harness.decode("utf-8") + ".cpp"

    log.log_info(f"Writing harness `{harness}` to workspace")
    with open(harness, "w+") as fd:
        fd.write(template)

    # interaction.show_message_box("Success", f"Done, wrote fuzzer harness to {harness}")
