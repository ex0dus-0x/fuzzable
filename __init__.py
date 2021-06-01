#!/usr/bin/env python3
"""
fuzzable.py

    Binary Ninja helper plugin for fuzzable target discovery.
"""
import os

import binaryninja
import binaryninja.log as log
import binaryninja.interaction as interaction

from binaryninja.enums import SymbolType
from binaryninja.plugin import BackgroundTaskThread, PluginCommand
from binaryninja.settings import Settings

from .analysis import FuzzableAnalysis

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
        "description"   : "Turn on if stripped functions are abundant and costly to analyze, and known to be irrelevant.",
        "type"          : "boolean",
        "default"       : false
    }
""",
)


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
        markdown_result = "# Fuzzable Targets\n | Function Name | Fuzzability | Coverage Depth | Recursive? |\n| :--- | :--- | :--- | :--- |\n"

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

            # instantiate module and add to parsed list
            analysis = FuzzableAnalysis(func)
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
    """ Callback used to instantiate thread and start analysis """
    task = WrapperTask(view)
    task.start()


def run_export_report(view):
    """ Generate a report from a previous analysis, and export as CSV """
    log.log_info("Attempting to export results to CSV")
    try:
        csv_output = view.query_metadata("csv")
    except KeyError:
        interaction.show_message_box("Error", "Cannot export without running an analysis first.")
        return

    # write last analysis to filepath
    csv_file = interaction.get_save_filename_input("Filename to export as CSV?", "csv")
    csv_file = csv_file.decode("utf-8") + ".csv"

    log.log_info(f"Writing to filepath {csv_file}")
    with open(csv_file, "w+") as fd:
        fd.write(csv_output)

    interaction.show_message_box("Success", f"Done, exported to {csv_file}")


def run_harness_generation(view, func):
    """ Experimental automatic fuzzer harness generation support """

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

    # replace templated portions of the template
    template = template.replace("{NAME}", func.name)
    template = template.replace("{RET_TYPE}", str(func.return_type))


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

PluginCommand.register_for_function(
    "Fuzzable\\Generate fuzzing harness (EXPERIMENTAL, C/C++ ONLY)",
    "For a target function, generate a AFL/libFuzzer C++ harness",
    run_harness_generation,
)
