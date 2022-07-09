#!/usr/bin/env python3
"""
__main__.py

    Command line entry point for launching the standalone CLI executable.
"""
import logging
import typing as t
import typer

from fuzzable import generate
from fuzzable.analysis import AnalysisBackend, AnalysisMode
from fuzzable.analysis.ast import AstAnalysis
from fuzzable.analysis.angr import AngrAnalysis

from pathlib import Path

# Supported source code paths
SOURCE_FILE_EXTS = [".c", ".cpp", ".cc", ".h", ".hpp"]

app = typer.Typer(
    help="Framework for Automating Fuzzable Target Discovery with Static Analysis"
)


@app.command()
def analyze(
    target: Path,
    mode: t.Optional[str] = typer.Option(
        "recommend",
        help="Analysis mode to run under (either `recommend` or `rank`, default is `recommend`)."
        "See docs for more details about which to select.",
    ),
    rec_export: t.Optional[bool] = typer.Option(
        False,
        help="If `--mode=recommend,` automatically attempt to generate harnesses for every candidate."
    ),
    out_csv: t.Optional[str] = typer.Option(
        "temp.csv",
        help="Export the analysis as a CSV to a path (default is `temp.csv`).",
    ),
):
    """
    Run fuzzable analysis on a single or workspace of C/C++ source files, or a binary.
    """
    try:
        mode = AnalysisMode[mode.upper()]
    except Exception:
        exception = typer.style(
            "Analysis mode must either be `recommend` or `rank`.",
            fg=typer.colors.WHITE,
            bg=typer.colors.RED,
        )
        typer.echo(exception)
        return None

    if target.is_file():
        run_on_file(target, mode)
    elif target.is_dir():
        run_on_workspace(target, mode)
    else:
        exception = typer.style(
            "Target path does not exist",
            fg=typer.colors.WHITE,
            bg=typer.colors.RED,
        )
        typer.echo(exception)


def run_on_file(target: Path, mode: AnalysisMode) -> None:
    """Runs analysis on a single source code file or binary file."""
    analyzer: t.TypeVar[AnalysisBackend]
    if target.suffix in SOURCE_FILE_EXTS:
        analyzer = AstAnalysis(target, mode)
    else:

        # prioritize loading binja as a backend, this may not
        # work if the license is personal/student.
        try:
            from binaryninja.binaryview import BinaryViewType
            from fuzzable.analysis.binja import BinjaAnalysis

            bv = BinaryViewType.get_view_of_file(target)
            bv.update_analysis_and_wait()
            analyzer = BinjaAnalysis(bv, mode, headless=True)

        # didn't work, try to load angr as a fallback instead
        # TODO: angr support
        except Exception as err:
            import angr

            typer.echo(
                f"Cannot load Binary Ninja as a backend. Reason: {err}. Attempting to load angr instead."
            )
            proj = angr.Project(target)
            analyzer = AngrAnalysis(proj, mode)
        else:
            exception = typer.style(
                "Unsupported file type. Must be either a binary or a C/C++ source",
                fg=typer.colors.WHITE,
                bg=typer.colors.RED,
            )
            typer.echo(exception)

    typer.echo(f"Running fuzzable analysis with {str(analyzer)} analyzer")
    analyzer.run()


def run_on_workspace(target: Path, mode: AnalysisMode) -> None:
    """
    Given a workspace, recursively iterate and parse out all of the source code files
    that are present. This is not currently supported on workspaces of binaries/libraries.
    """
    source_files = []
    for file in target.iterdir():
        if file.suffix in SOURCE_FILE_EXTS:
            source_files += [file]

    if len(source_files) == 0:
        exception = typer.style(
            "No C/C++ source code found in the workspace. fuzzable currently does not support parsing on workspaces with multiple binaries.",
            fg=typer.colors.WHITE,
            bg=typer.colors.RED,
        )
        typer.echo(exception)
        return

    for path in source_files:
        print(target / path)


@app.command()
def create_harness(
    target: Path,
    symbol_name: str = typer.Option(
        "", help="Name of function symbol to create a fuzzing harness to target."
    ),
    file_fuzzing: bool = typer.Option(
        False,
        help="If enabled, will generate a harness that takes a filename parameter instead of reading from STDIN.",
    ),
    libfuzzer: bool = typer.Option(
        False,
        help="If enabled, will set the flag that compiles the harness as a libFuzzer harness instead of for AFL.",
    ),
):
    """Synthesize a AFL++/libFuzzer harness for a given symbol in a target."""

    # if a binary, check if executable or library. if executable, use LIEF to
    # copy, export the symbol and transform to shared object.

    # if source code, use the generic library

    print(target, symbol_name)
