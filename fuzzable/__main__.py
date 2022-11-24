#!/usr/bin/env python3
"""
__main__.py

    Command line entry point for launching the standalone CLI executable.
"""
import os
import logging
import typing as t
import typer

from rich import print

from fuzzable import generate
from fuzzable.config import SOURCE_FILE_EXTS
from fuzzable.cli import print_table, error, export_results
from fuzzable.analysis import AnalysisBackend, DEFAULT_SCORE_WEIGHTS
from fuzzable.analysis.ast import AstAnalysis
from fuzzable.log import log

from pathlib import Path

app = typer.Typer(
    help="Framework for Automating Fuzzable Target Discovery with Static Analysis",
    no_args_is_help=True,
    context_settings=dict(help_option_names=["-h", "--help"]),
    add_completion=False,
)


@app.callback()
def global_args(
    verbosity: int = typer.Option(
        0,
        "-v",
        "--verbosity",
        help="Sets logging level (2 = debug, 1 = info, 0 = output).",
    ),
):
    """Handles global flags for all commands."""
    if verbosity == 1:
        log.setLevel(logging.INFO)
    elif verbosity == 2:
        log.setLevel(logging.DEBUG)


@app.command()
def analyze(
    target: Path,
    export: t.Optional[Path] = typer.Option(
        None,
        "-e",
        "--export",
        help="Export the fuzzability report to a path based on the file extension."
        "Fuzzable supports exporting to `json`, `csv`, or `md`.",
    ),
    list_ignored: bool = typer.Option(
        False,
        help="If set, will also additionally output and/or export ignored symbols.",
    ),
    include_sym: t.Optional[str] = typer.Option(
        None,
        help="Comma-seperated list of symbols to absolutely be considered for analysis.",
    ),
    include_nontop: bool = typer.Option(
        False, help="If set, won't filter out only on top-level function definitions."
    ),
    skip_sym: t.Optional[str] = typer.Option(
        None, help="Comma-seperated list of symbols to skip during analysis."
    ),
    skip_stripped: bool = typer.Option(
        False,
        help="If set, ignore symbols that are stripped in binary analysis."
        "Will be ignored if fuzzability analysis is done on source code.",
    ),
    ignore_metrics: bool = typer.Option(
        True,
        help="If set, include individual metrics' scores for each function target analyzed.",
    ),
    score_weights: t.Optional[str] = typer.Option(
        None,
        "-w",
        "--score-weights",
        help="Comma-seperated list of reconfigured weights for multi-criteria decision analysis when determining fuzzability.",
    ),
):
    """
    Run fuzzable analysis on a single or workspace of C/C++ source files, or a compiled binary.
    """
    if not target.is_file() and not target.is_dir():
        error(f"Target path `{target}` does not exist.")

    # parse custom weights and run checks
    if score_weights:
        log.debug("Reconfiguring score weights for MCDA")
        score_weights = [float(weight) for weight in score_weights.split(",")]
        num_weights = len(DEFAULT_SCORE_WEIGHTS)
        if len(score_weights) != num_weights:
            error(f"--score-weights must contain {num_weights}")

        if sum(score_weights) != 1.0:
            error(f"--score-weights must sum up to 1.0")
    else:
        score_weights = DEFAULT_SCORE_WEIGHTS

    # export file format checking
    if export is not None:
        ext = export.suffix.lower()[1:]
        if ext not in ["json", "csv", "md"]:
            error("--export value must either have `json`, `csv`, or `md` extensions.")

    # parse symbols to explicitly include for analysis
    if include_sym:
        include_sym = [sym for sym in include_sym.split(",")]
        if len(include_sym) == 0:
            error(f"--include-sym must include at least one valid function symbol")

        log.debug(f"Parsed symbols to explicitly include for analysis {include_sym}")
    else:
        include_sym = []

    # parse symbols to explicitly exclude from analysis
    if skip_sym:
        skip_sym = [sym for sym in skip_sym.split(",")]
        if len(skip_sym) == 0:
            error(f"--skip-sym must specify a valid function symbol")

        log.debug(f"Parsed symbols to explicitly include for analysis {skip_sym}")
    else:
        skip_sym = []

    # check if overlapping symbols
    if set(skip_sym) & set(include_sym):
        error(f"Cannot have same symbols in both --include-sym and --skip-sym.")

    log.info(f"Running fuzzability analysis on {target}")
    if target.is_file():
        run_on_file(
            target,
            export,
            list_ignored,
            include_sym,
            include_nontop,
            skip_sym,
            skip_stripped,
            ignore_metrics,
            score_weights,
        )
    elif target.is_dir():
        run_on_workspace(
            target,
            export,
            list_ignored,
            include_sym,
            include_nontop,
            skip_sym,
            skip_stripped,
            ignore_metrics,
            score_weights,
        )


def run_on_file(
    target: Path,
    export: t.Optional[Path],
    list_ignored: bool,
    include_sym: t.List[str],
    include_nontop: bool,
    skip_sym: t.List[str],
    skip_stripped: bool,
    ignore_metrics: bool,
    score_weights: t.List[float],
) -> None:
    """Runs analysis on a single source code file or binary file."""
    analyzer: t.TypeVar[AnalysisBackend]

    extension = target.suffix
    if extension in SOURCE_FILE_EXTS:
        analyzer = AstAnalysis(
            [target],
            include_sym=include_sym,
            include_nontop=include_nontop,
            score_weights=score_weights,
        )
    else:

        # Prioritize loading binja as a backend, this will not
        # work if the license is personal/student.
        try:
            import sys

            sys.tracebacklimit = 0

            from binaryninja.binaryview import BinaryViewType

            bv = BinaryViewType.get_view_of_file(target)
            bv.update_analysis_and_wait()

            from fuzzable.analysis.binja import BinjaAnalysis

            analyzer = BinjaAnalysis(
                bv,
                include_sym=include_sym,
                include_nontop=include_nontop,
                skip_sym=skip_sym,
                skip_stripped=skip_stripped,
                score_weights=score_weights,
                headless=True,
            )

        # didn't work, try to load angr as a fallback instead
        except (RuntimeError, ModuleNotFoundError, ImportError):
            log.warning(
                f"Cannot load Binary Ninja as a backend. Attempting to load angr instead."
            )
            try:
                from fuzzable.analysis.angr import AngrAnalysis

                analyzer = AngrAnalysis(
                    target,
                    include_sym=include_sym,
                    include_nontop=include_nontop,
                    skip_sym=skip_sym,
                    skip_stripped=skip_stripped,
                    score_weights=score_weights,
                )
            except ModuleNotFoundError as err:
                error(f"Unsupported target {target}. Reason: {err}")

    log.info(f"Running fuzzable analysis with the {str(analyzer)} analyzer")
    results = analyzer.run()
    print_table(target, results, analyzer.skipped, ignore_metrics, list_ignored)
    if export:
        export_results(export, results)


def run_on_workspace(
    target: Path,
    export: t.Optional[Path],
    list_ignored: bool,
    include_sym: t.List[str],
    include_nontop: bool,
    skip_sym: t.List[str],
    skip_stripped: bool,  # not used, maybe until we support multiple binaries
    ignore_metrics: bool,
    score_weights: t.List[float],
) -> None:
    """
    Given a workspace, recursively iterate and parse out all of the source code files
    that are present. This is not currently supported on workspaces of binaries/libraries.
    """
    source_files = []
    for subdir, _, files in os.walk(target):
        for file in files:
            if Path(file).suffix in SOURCE_FILE_EXTS:
                log.info(f"Adding {file} to set of source code to analyze")
                source_files += [Path(os.path.join(subdir, file))]

    if len(source_files) == 0:
        error(
            "No C/C++ source code found in the workspace. fuzzable currently does not support parsing on workspaces with multiple binaries."
        )

    analyzer = AstAnalysis(
        source_files,
        include_sym=include_sym,
        include_nontop=include_nontop,
        skip_sym=skip_sym,
        score_weights=score_weights,
        basedir=target,
    )
    log.info(f"Running fuzzable analysis with the {str(analyzer)} analyzer")
    results = analyzer.run()
    print_table(target, results, analyzer.skipped, ignore_metrics, list_ignored)
    if export:
        export_results(export, results)


@app.command()
def create_harness(
    target: Path,
    symbol_name: str = typer.Option(
        ...,
        "-n",
        "--symbol_name",
        help="Names of function symbol to create a fuzzing harness to target. Source not supported yet.",
    ),
    out_so_name: t.Optional[Path] = typer.Option(
        None,
        "-s",
        "--out_so_name",
        help="Specify to set output `.so` path of a transformed ELF binary for binary targets.",
    ),
    out_harness: t.Optional[Path] = typer.Option(
        None,
        "-o",
        "--out_harness",
        help="Specify to set output harness template file path.",
    ),
):
    """Synthesize a AFL++/libFuzzer harness for a given symbol in a binary target."""

    if not target.is_file():
        error(f"Target path `{target}` does not exist.")

    try:
        import lief
    except (RuntimeError, ModuleNotFoundError, ImportError):
        error("Could not import LIEF library to parse binary.")

    # if a binary, check if executable or library. if executable, use LIEF to
    # copy, export the symbol and transform to shared object.
    binary = lief.parse(target)
    if binary is None:
        error(
            "Wrong filetype, or does not support synthesizing harnesses for C/C++ source code yet."
        )

    # resolve paths appropriately
    if out_so_name:
        out_so_name = out_so_name.expanduser()

    if out_harness:
        out_harness = out_harness.expanduser()

    log.info(f"Running harness generation for `{target}` on symbol `{symbol_name}`.")
    shared_obj = generate.transform_elf_to_so(target, binary, symbol_name, out_so_name)
    generate.generate_harness(shared_obj, symbol_name, output=out_harness)

    log.info("Done!")
