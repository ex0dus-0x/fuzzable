#!/usr/bin/env python3
"""
__main__.py

    Command line entry point for launching the standalone CLI executable.
"""
import logging
import typing as t
import typer

from fuzzable.analysis import AnalysisBackend
from fuzzable.analysis.ast import AstAnalysis
from fuzzable.analysis.angr import AngrAnalysis

# Attempt to load Binary Ninja as the main disassembly backend.
# If not available, angr will be the fallback.
BINJA = False
try:
    import binaryninja
    from fuzzable.analysis.binja import BinjaAnalysis

    BINJA = True
except ImportError:
    import angr

from pathlib import Path

# Supported source code paths
SOURCE_FILE_EXTS = [".c", ".cpp", ".cc", ".h", ".hpp"]

app = typer.Typer(
    help="Framework for Automating Fuzzable Target Discovery with Static Analysis"
)


@app.command()
def analyze(
    target: Path,
    mode: t.Optional[str] = typer.Option("", help=""),
    export: t.Optional[str] = typer.Option("", help=""),
):
    """
    Run fuzzable analysis on a single or workspace of C/C++ source files, or a binary.
    """

    if target.is_file():
        run_on_file(target)
    elif target.is_dir():
        run_on_workspace(target)
    else:
        exception = typer.style(
            "Target path does not exist",
            fg=typer.colors.WHITE,
            bg=typer.colors.RED,
        )
        typer.echo(exception)


def run_on_file(target: Path) -> None:
    """
    Runs analysis on a single source or binary file. Helps determine the disassembly backend.
    """
    analyzer: t.TypeVar[AnalysisBackend]
    if target.suffix in SOURCE_FILE_EXTS:
        analyzer = AstAnalysis(target)
    else:
        try:
            if BINJA:
                bv = binaryninja.open(target)
                bv.update_analysis_and_wait()
                analyzer = BinjaAnalysis(bv)

            # TODO: angr support
            else:
                proj = angr.Project(target)
                analyzer = AngrAnalysis(proj)
                raise Exception("angr support is work-in-progress at the moment.")

        except Exception:
            exception = typer.style(
                "Unsupported file type. Must be either a binary or a C/C++ source",
                fg=typer.colors.WHITE,
                bg=typer.colors.RED,
            )
            typer.echo(exception)

    typer.echo(f"Running fuzzable analysis with {str(analyzer)} analyzer")
    analyzer.run(headless=True)


def run_on_workspace(target: Path) -> None:
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
def create_harness(target: Path, symbol_name: str, libfuzzer: bool = False):
    """Synthesize a AFL++/libFuzzer harness for a given symbol in a target."""
    print(target, symbol_name)