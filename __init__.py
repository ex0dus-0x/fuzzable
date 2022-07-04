#!/usr/bin/env python3
"""
__init__.py

    Plugin module used for Binary Ninja
"""
from binaryninja.plugin import PluginCommand
from binaryninja.settings import Settings

from fuzzable.analysis import binja

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
    "fuzzable.loop_increase_score",
    """
    {
        "title"         : "Don't score natural loop presence",
        "description"   : "Don't include natural loop as part of the fuzzability score",
        "type"          : "boolean",
        "default"       : false
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

PluginCommand.register(
    "Fuzzable\\Analysis\\Analyze & Rank All Fuzzable Targets",
    "Identify and generate targets for fuzzing",
    binja.run_fuzzable,
)

PluginCommand.register(
    "Fuzzable\\Analysis\\Analyze & Rank High Risk Fuzzable targets",
    "Identify and generate targets for fuzzing",
    binja.run_fuzzable,
)

PluginCommand.register(
    "Fuzzable\\Export\\Fuzzability Report\\Export as CSV",
    "Identify and generate targets for fuzzing",
    binja.run_export_report,
)

PluginCommand.register(
    "Fuzzable\\Export\\Fuzzability Report\\Export as Markdown",
    "Identify and generate targets for fuzzing",
    binja.run_export_report,
)

PluginCommand.register(
    "Fuzzable\\Export\\Signatures\\Export for highlighted function",
    "Identify and generate targets for fuzzing",
    binja.run_export_report,
)

PluginCommand.register_for_function(
    "Fuzzable\\Harness Generation\\Generate fuzzing harness (EXPERIMENTAL, C/C++ ONLY)",
    "For a target function, generate a AFL/libFuzzer C++ harness",
    binja.run_harness_generation,
)
