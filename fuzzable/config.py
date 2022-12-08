"""
config.py

    Defines configuration knobs that can be universally configured by
    any fuzzable client
"""
import typing as t

import typer

from dataclasses import dataclass
from pathlib import Path


def get_project_root() -> Path:
    """Utility for getting root directory of this project"""
    return Path(__file__).parent.parent


@dataclass
class AnalysisKnobs:
    export: t.Optional[Path] = (
        typer.Option(
            None,
            "-e",
            "--export",
            help="Export the fuzzability report to a path based on the file extension."
            "Fuzzable supports exporting to `json`, `csv`, or `md`.",
        ),
    )
    list_ignored: bool = (
        typer.Option(
            False,
            help="If set, will also additionally output and/or export ignored symbols.",
        ),
    )
    include_sym: t.Optional[str] = (
        typer.Option(
            None,
            help="Comma-seperated list of symbols to absolutely be considered for analysis.",
        ),
    )
    include_nontop: bool = (
        typer.Option(
            False,
            help="If set, won't filter out only on top-level function definitions.",
        ),
    )
    skip_sym: t.Optional[str] = (
        typer.Option(
            None, help="Comma-seperated list of symbols to skip during analysis."
        ),
    )
    skip_stripped: bool = (
        typer.Option(
            False,
            help="If set, ignore symbols that are stripped in binary analysis."
            "Will be ignored if fuzzability analysis is done on source code.",
        ),
    )
    ignore_metrics: bool = (
        typer.Option(
            True,
            help="If set, include individual metrics' scores for each function target analyzed.",
        ),
    )
    score_weights: t.Optional[str] = (
        typer.Option(
            None,
            "-w",
            "--score-weights",
            help="Comma-seperated list of reconfigured weights for multi-criteria decision analysis when determining fuzzability.",
        ),
    )


# Supported C/C++ source code extensions
# TODO: we should do a very initial parse on the file to determine if it is C++ source
SOURCE_FILE_EXTS: t.List[str] = [".c", ".cpp", ".cc", ".cp" ".cxx", ".h", ".hpp", ".hh"]

GLOBAL_IGNORES: t.List[str] = [
    "__cxa_finalize",
    "__gmon_start__",
    "_init",
    "_fini",
    "frame_dummy",
    "call_weak_fn",
    "register_tm_clones",
    "$x",
]

# Interesting symbol name patterns to check for fuzzable
INTERESTING_PATTERNS: t.List[str] = [
    # Consuming Inputs
    "parse",
    "read",
    "buf",
    "file",
    "input",
    "str",
    # Decryption Routines
    "encode",
    "decode",
    # Other stuff
    "draw",
    "image",
    "img",
    "load",
    "url",
]

# Function name patterns that include INTERESTING_PATTERNS but
# may not be very useful/interesting to us
FALSE_POSITIVE_SIMILARS: t.List[str] = [
    # str
    "destroy"
]

# Data sink call names that should be deemed risky
# TODO: dataset of risky function calls
RISKY_GLIBC_CALL_PATTERNS: t.List[str] = [
    "cmp",
    "cpy",
    "alloc",
    "create",
]
