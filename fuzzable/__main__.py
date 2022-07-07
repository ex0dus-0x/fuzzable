#!/usr/bin/env python3
"""
__main__.py

    Command line entry point for launching the standalone CLI executable.
"""
import logging
import typing as t
import typer

from fuzzable.analysis import *

# Attempt to load Binary Ninja as the main disassembly backend.
# If not available, angr will be the fallback.
BINJA = False
try:
    import binaryninja

    BINJA = True
except ImportError:
    import angr

from pathlib import Path

SOURCE_FILE_EXTS = [".c", ".cpp", ".cc", ".h", ".hpp"]

app = typer.Typer(
    help="Framework for Automating Fuzzable Target Discovery with Static Analysis"
)


@app.command()
def main(
    target: Path,
    recommend: bool = typer.Option("", help=""),
    rank: bool = typer.Option("", help="If set, rank"),
):
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
    Runs analysis on source or binary file. Helps determine the disassembly backend.
    """
    if target.suffix in SOURCE_FILE_EXTS:

        return

    try:
        if BINJA:
            _ = binaryninja.open(target)
        else:
            _ = angr.Project(target)
    except Exception:
        exception = typer.style(
            "Unsupported file type. Must be either a binary or a C/C++ source",
            fg=typer.colors.WHITE,
            bg=typer.colors.RED,
        )
        typer.echo(exception)


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
