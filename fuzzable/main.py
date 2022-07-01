#!/usr/bin/env python3
"""
__main__.py

    Command line entry point for launching the standalone CLI executable.
"""
import logging
import typing as t
import typer

# Attempt to load Binary Ninja as the main disassembly backend.
# If not available, angr will be the fallback.
BINJA = False
try:
    import binaryninja

    BINJA = True
except ImportError:
    import angr

from pathlib import Path

SOURCE_FILE_EXTS = ["c", "cpp", "cc", "h", "hpp"]

app = typer.Typer(
    help="Framework for Automating Fuzzable Target Discovery with Static Analysis"
)


@app.command()
def main(target: Path):
    if target.is_file():
        run_on_file(target)
    elif target.is_dir():
        run_on_workspace(target)
    else:
        typer.echo("Target path does not exist.")


def run_on_file(target: Path):
    if target.suffix in SOURCE_FILE_EXTS:
        return

    try:
        if BINJA:
            binary = binaryninja.open(target)
        else:
            binary = angr.Project(target)
    except Exception:
        exception = typer.style("bad", fg=typer.colors.WHITE, bg=typer.colors.RED)
        typer.echo(exception)


def run_on_workspace(target: Path):
    """ """
    source_files = []
    for file in target.iterdir():
        if file.suffix in SOURCE_FILE_EXTS:
            source_files += [file]

    if len(source_files) == 0:
        typer.echo("")
