#!/usr/bin/env python3
"""
__main__.py

    Command line entry point for launching the standalone CLI executable.
"""
import os
import logging
import typing as t
import typer
import lief

from rich import print

from fuzzable import generate
from fuzzable.config import SOURCE_FILE_EXTS
from fuzzable.cli import print_table, error, export_results
from fuzzable.analysis import AnalysisBackend, DEFAULT_SCORE_WEIGHTS
from fuzzable.analysis.ast import AstAnalysis
from fuzzable.log import log

from pathlib import Path

app = typer.Typer(
    help="Framework for Automating Fuzzable Target Discovery with Static Analysis"
)


@app.command()
def analyze(
    target: Path,
    backend: t.Optional[str] = typer.Option(
        None, help="Set the backend to use automatically (will error if incompatible)."
    ),
    export: t.Optional[Path] = typer.Option(
        None,
        help="Export the fuzzability report to a path based on the file extension."
        "Fuzzable supports exporting to `json`, `csv`, or `md`.",
    ),
    include_sym: t.Optional[str] = typer.Option(
        None,
        help="Include symbols that are accidentally ignored to be considered for analysis.",
    ),
    include_nontop: bool = typer.Option(
        False, help="If set, won't filter out only on top-level function definitions."
    ),
    list_ignored: bool = typer.Option(
        False,
        help="If set, will also additionally output and/or export ignored symbols.",
    ),
    skip_stripped: bool = typer.Option(
        False,
        help="If set, ignore symbols that are stripped in binary analysis."
        "Will be ignored if fuzzability analysis is done on source code.",
    ),
    score_weights: t.Optional[str] = typer.Option(
        None,
        help="Reconfigure the weights for multi-criteria decision analysis when determining fuzzability.",
    ),
    debug: bool = typer.Option(
        False,
        help="If set, will be verbose and output debug information.",
    ),
):
    """
    Run fuzzable analysis on a single or workspace of C/C++ source files, or a compiled binary.
    """
    if debug:
        log.setLevel(logging.DEBUG)

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

    # parse symbols to explicitly include analysis
    if include_sym:
        log.debug("Parsing symbols to include")
        include_sym = [sym for sym in include_sym.split(",")]
        if len(include_sym) == 0:
            error(f"--include_sym must specify a valid function symbol")
    else:
        include_sym = []

    log.info(f"Running fuzzability analysis on {target}")
    if target.is_file():
        run_on_file(
            target,
            score_weights,
            include_sym,
            include_nontop,
            export,
            list_ignored,
            skip_stripped,
        )
    elif target.is_dir():
        run_on_workspace(
            target, score_weights, include_sym, include_nontop, export, list_ignored
        )


def run_on_file(
    target: Path,
    score_weights: t.List[float],
    include_sym: t.List[str],
    include_nontop: bool,
    export: t.Optional[Path],
    list_ignored: bool,
    skip_stripped: bool,
) -> None:
    """Runs analysis on a single source code file or binary file."""
    analyzer: t.TypeVar[AnalysisBackend]

    extension = target.suffix
    if extension in SOURCE_FILE_EXTS:
        analyzer = AstAnalysis([target], score_weights=score_weights)
    else:

        # Prioritize loading binja as a backend, this may not
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
                score_weights=score_weights,
                skip_stripped=skip_stripped,
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
                    score_weights=score_weights,
                    skip_stripped=True,
                )
            except ModuleNotFoundError as err:
                error(f"Unsupported target {target}. Reason: {err}")

    log.info(f"Running fuzzable analysis with the {str(analyzer)} analyzer")
    results = analyzer.run()
    print_table(target, results, analyzer.skipped, list_ignored)
    if export:
        export_results(export, results)


def run_on_workspace(
    target: Path,
    score_weights: t.List[float],
    include_sym: t.List[str],
    include_nontop: bool,
    export: t.Optional[Path],
    list_ignored: bool,
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
        source_files, mode, score_weights=score_weights, basedir=target
    )
    log.info(f"Running fuzzable analysis with the {str(analyzer)} analyzer")
    results = analyzer.run()
    print_table(target, results, analyzer.skipped, list_ignored)
    if export:
        export_results(export, results)


@app.command()
def create_harness(
    target: str,
    symbol_name: str = typer.Option(
        "",
        help="Names of function symbol to create a fuzzing harness to target. Source not supported yet.",
    ),
    out_so_name: t.Optional[Path] = typer.Option(
        None,
        help="Specify to set output `.so` path of a transformed ELF binary for binary targets.",
    ),
    out_harness: t.Optional[Path] = typer.Option(
        None, help="Specify to set output harness template file path."
    ),
    debug: bool = typer.Option(
        False,
        help="If set, will be verbose and output debug information.",
    ),
):
    """Synthesize a AFL++/libFuzzer harness for a given symbol in a target."""
    if debug:
        log.setLevel(logging.DEBUG)

    if not symbol_name:
        error("No --symbol-name specified.")

    # if a binary, check if executable or library. if executable, use LIEF to
    # copy, export the symbol and transform to shared object.
    binary = lief.parse(target)
    if binary is None:
        error(
            "Wrong filetype, or does not support synthesizing harnesses for C/C++ source code yet."
        )

    # resolve paths appropriately
    target = Path(target)
    if out_so_name:
        out_so_name = out_so_name.expanduser()

    if out_harness:
        out_harness = out_harness.expanduser()

    log.info(f"Running harness generation for `{target}` on symbol `{symbol_name}`.")
    shared_obj = generate.transform_elf_to_so(target, binary, symbol_name, out_so_name)
    generate.generate_harness(shared_obj, symbol_name, output=out_harness)

    log.info("Done!")
