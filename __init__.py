#!/usr/bin/env python3
"""
__init__.py

    Plugin module used for Binary Ninja
"""
from binaryninja.plugin import PluginCommand
from binaryninja.settings import Settings

from .fuzzable.analysis import binja, DEFAULT_SCORE_WEIGHTS

# TODO register settings from a config of analysis flags

Settings().register_group("fuzzable", "Fuzzable")
Settings().register_setting(
    "fuzzable.include_sym",
    """
    {
        "title"         : "Symbols to Include",
        "description"   : "Include symbols that are accidentally ignored to be considered for analysis.",
        "type"          : "array",
        "elementType"   : "string",
        "default"       : []
    }
""",
)

Settings().register_setting(
    "fuzzable.include_nontop",
    """
    {
        "title"         : "Include non-top level calls",
        "description"   : "If set, won't filter out only on top-level function definitions.",
        "type"          : "boolean",
        "default"       : false
    }
""",
)

Settings().register_setting(
    "fuzzable.skip_sym",
    """
    {
        "title"         : "Symbols to Exclude",
        "description"   : "Exclude symbols from being considered for analaysis.",
        "type"          : "array",
        "elementType"   : "string",
        "default"       : []
    }
""",
)

Settings().register_setting(
    "fuzzable.skip_stripped",
    """
    {
        "title"         : "Skip Stripped Symbols",
        "description"   : "Ignore stripped symbols.",
        "type"          : "boolean",
        "default"       : false
    }
""",
)

Settings().register_setting(
    "fuzzable.list_ignored",
    """
    {
        "title"         : "List Ignored Symbols",
        "description"   : "Include the symbols that we've ignored using `recommend` mode.",
        "type"          : "boolean",
        "default"       : false
    }
""",
)

Settings().register_setting(
    "fuzzable.score_weights",
    """
    {
        "title"         : "Override Score Weights",
        "description"   : "Change default score weights for each metric.",
        "type"          : "array",
        "elementType"   : "string",
        "default"       : {}
    }
""".format(
        DEFAULT_SCORE_WEIGHTS
    ),
)

PluginCommand.register(
    "Fuzzable\\Analyze & Rank Function",
    "List out functions we've determined to be the best candidates for fuzzing."
    "This will exclude functions that is determined to not be directly usable for a harness.",
    binja.run_fuzzable,
)

PluginCommand.register(
    "Fuzzable\\Export Fuzzability Report\\CSV (.csv)",
    "Identify and generate targets for fuzzing",
    binja.run_export_csv,
)

PluginCommand.register(
    "Fuzzable\\Export Fuzzability Report\\JSON (.json)",
    "Identify and generate targets for fuzzing",
    binja.run_export_json,
)

PluginCommand.register(
    "Fuzzable\\Export Fuzzability Report\\Markdown (.md)",
    "Identify and generate targets for fuzzing",
    binja.run_export_md,
)

PluginCommand.register_for_function(
    "Fuzzable\\Harness Generation\\Generate binary fuzzing harness (Linux ONLY at the moment)",
    "For a target function, generate a AFL-QEMU/libFuzzer C++ harness",
    binja.run_harness_generation,
)
