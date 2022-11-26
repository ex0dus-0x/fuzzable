"""
binja.py

    Fuzzable analysis support for the Binary Ninja disassembler. Can be invoked both through 
    registered plugin handlers, and through a headless standalone CLI.

"""
import os
import typing as t
import lief

from pathlib import Path

import binaryninja
import binaryninja.log as log
import binaryninja.interaction as interaction
import binaryninja.demangle as demangle

from binaryninja import BinaryView
from binaryninja.architecture import Architecture
from binaryninja.function import Function
from binaryninja.lowlevelil import LowLevelILReg
from binaryninja.enums import LowLevelILOperation, SymbolType
from binaryninja.plugin import BackgroundTaskThread
from binaryninja.settings import Settings

from .. import generate
from . import AnalysisBackend, Fuzzability, DEFAULT_SCORE_WEIGHTS
from ..metrics import CallScore, METRICS


class _BinjaAnalysisMeta(type(AnalysisBackend), type(BackgroundTaskThread)):
    pass


class BinjaAnalysis(
    AnalysisBackend, BackgroundTaskThread, metaclass=_BinjaAnalysisMeta
):
    """Derived class to support Binary Ninja, and can be dispatched as a task from the plugin."""

    def __init__(
        self,
        target: BinaryView,
        include_sym: t.List[str] = [],
        include_nontop: bool = False,
        skip_sym: t.List[str] = [],
        skip_stripped: bool = False,
        score_weights: t.List[float] = DEFAULT_SCORE_WEIGHTS,
        headless: bool = False,
    ):
        AnalysisBackend.__init__(
            self,
            target,
            include_sym,
            include_nontop,
            skip_sym,
            skip_stripped,
            score_weights,
        )
        BackgroundTaskThread.__init__(
            self, "Finding fuzzable targets in current binary view"
        )
        self.view: BinaryView = target
        self.headless: bool = headless

    def __str__(self) -> str:
        return "Binary Ninja"

    def run(self) -> t.Optional[Fuzzability]:
        self.view.update_analysis_and_wait()
        funcs = self.view.functions

        log.log_info(f"Starting fuzzable analysis over {len(funcs)} symbols in binary")
        for func in funcs:

            # demangle the symbol name
            _, name = demangle.demangle_ms(Architecture["x86_64"], func.name)
            name = demangle.get_qualified_name(name)
            addr = str(hex(func.address_ranges[0].start))

            log.log_debug(f"Checking to see if we should ignore {name}")
            if self.skip_analysis(func):
                log.log_warn(f"Skipping {name} from fuzzability analysis.")
                self.skipped[name] = addr
                continue

            log.log_debug(f"Checking to see if {name} is a top-level call")
            if not self.include_nontop and self.is_toplevel_call(func):
                log.log_warn(
                    f"Skipping {name} (not top-level) from fuzzability analysis."
                )
                self.skipped[name] = addr
                continue

            log.log_info(f"Starting analysis for function {name}")
            score = self.analyze_call(name, func)
            self.scores += [score]

        log.log_info("Done, ranking the analyzed calls for reporting")
        ranked = super()._rank_fuzzability(self.scores)

        # if headless, handle displaying results back
        if not self.headless:
            csv_result = ",".join([metric.identifier for metric in METRICS])

            columns = [metric.friendly_name for metric in METRICS]
            csv_result = ", ".join([f'"{column}"' for column in columns])

            # TODO: reuse rich for markdown
            markdown_result = f"""# Fuzzable Targets

This is a generated report that ranks fuzzability of every parsed symbol that was recovered in this binary. If you feel that the results
are incomplete, wait for Binary Ninja's initial analysis to finalize and re-run this feature in the plugin.

__Number of Symbols Analyzed:__ {len(ranked)}

__Number of Symbols Skipped:__ {len(self.skipped)}

__Top Fuzzing Contender:__ [{ranked[0].name}](binaryninja://?expr={ranked[0].name})

## Ranked Table (MODE = {self.mode.name})

| Function Signature | Location          | Fuzzability Score | Fuzz-Friendly Name | Risky Data Sinks | Natural Loops | Cyclomatic Complexity | Coverage Depth |
|--------------------|-------------------|-------------------|--------------------|------------------|---------------|-----------------------|----------------|
"""
            for score in ranked:
                markdown_result += score.binja_markdown_row
                csv_result += score.csv_row

            # if set include list of ignored symbols
            if Settings().get_bool("fuzzable.list_ignored"):
                markdown_result += "\n## Ignored Symbols\n"
                for name, loc in self.skipped.items():
                    markdown_result += f"* [{name}](binaryninja://?expr={loc})"

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
            loc=str(hex(func.address_ranges[0].start)),
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
        log.log_debug(f"Checking if we should skip {name} ({symbol})")

        if super().skip_analysis(name):
            return True

        # ignore imported functions from other libraries, ie glibc or win32api
        if symbol in [
            SymbolType.ImportedFunctionSymbol,
            SymbolType.LibraryFunctionSymbol,
            SymbolType.ImportAddressSymbol,
            SymbolType.ImportedFunctionSymbol,
            SymbolType.ImportedDataSymbol,
        ]:
            log.log_debug(f"{name} is an import, skipping")
            return True

        return False

    def is_toplevel_call(self, target: Function) -> bool:
        return len(target.callers) == 0

    def risky_sinks(self, func: Function) -> int:
        """
        Find references of known insecure/risky calls, and check to see if there is an
        argument in the function call that flows into it. Will treat the current function
        target under an interprocedural analysis.
        """

        risky_sinks = 0
        visited = []

        # visit all other calls with depth-first search until we reach a risky sink
        callstack = [func]
        while callstack:
            func = callstack.pop()

            # Iterate over each argument and check for taint sinks
            for arg in func.parameter_vars:

                # if arg.type != "char*":
                #    continue

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
                        elif callee.name not in visited:
                            callstack += [callee]

                        visited += [callee.name]

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

                # ignore recursive calls
                if child.name == target.name:
                    continue

                # if address attempt to resolve call
                if child.name not in self.visited:
                    callstack += [child]

            self.visited += [func.name]

        return depth

    def natural_loops(self, target: Function) -> int:
        return len([bb in bb.dominance_frontier for bb in target.basic_blocks])

    def get_cyclomatic_complexity(self, func: Function) -> int:
        num_blocks = len(func.basic_blocks)
        num_edges = sum([len(b.outgoing_edges) for b in func.basic_blocks])
        return num_edges - num_blocks + 2


def run_fuzzable(view) -> None:
    settings = Settings()
    task = BinjaAnalysis(
        view,
        include_sym=settings.get_array("fuzzable.include_sym"),
        include_nontop=settings.get_bool("fuzzable.include_nontop"),
        skip_sym=settings.get_array("fuzzable.skip_sym"),
        skip_stripped=settings.get_bool("fuzzable.skip_stripped"),
        score_weights=settings.get_array("fuzzable.score_weights"),
    )
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
    with open(csv_file, "w+", encoding="utf-8") as csv_fd:
        csv_fd.write(csv_output)

    interaction.show_message_box("Success", f"Done, exported to {csv_file}")


def run_export_json(view: BinaryView) -> None:
    """Generate a JSON report from a previous analysis"""
    log.log_info("Attempting to export results to JSON")
    try:
        json_output = view.query_metadata("json")
    except KeyError:
        interaction.show_message_box(
            "Error", "Cannot export without running an analysis first."
        )
        return

    json_file = interaction.get_save_filename_input(
        "Filename to export as JSON?", "json"
    )
    json_file = json_file.decode("utf-8") + ".csv"

    log.log_info(f"Writing to filepath {json_file}")
    with open(json_file, "w+", encoding="utf-8") as json_fd:
        json_fd.write(json_output)

    interaction.show_message_box("Success", f"Done, exported to {json_file}")


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
    with open(md_file, "w+", encoding="utf-8") as mkdown:
        mkdown.write(markdown_output)

    interaction.show_message_box("Success", f"Done, exported to {md_file}")


def run_harness_generation(view, func: Function) -> None:
    """Experimental automatic fuzzer harness generation support"""

    log.log_debug("Grabbing closed-source template from project folder")
    template_file = os.path.join(
        binaryninja.user_plugin_path(),
        "fuzzable/templates/linux_closed_source_harness.cpp",
    )

    path = view.file.filename
    binary = lief.parse(path)

    symbol = func.name
    params: t.List[str] = [f"{param.type}" for param in func.parameter_vars.vars]
    return_type = str(func.return_type)

    log.log_debug("Getting filename to write to")
    harness = interaction.get_save_filename_input("Path to write to?", "cpp", "")
    harness = harness + ".cpp"

    log.log_info("Generating harness from template")

    # if stripped, get the address instead as the symbol
    if "sub_" in symbol:
        symbol = hex(func.address_ranges[0].start)

    shared_obj = generate.transform_elf_to_so(Path(path), binary, symbol)
    generate.generate_harness(
        shared_obj,
        symbol,
        return_type=return_type,
        params=params,
        harness_path=template_file,
        output=harness,
    )

    interaction.show_message_box("Success", f"Done, wrote fuzzer harness to {harness}")
