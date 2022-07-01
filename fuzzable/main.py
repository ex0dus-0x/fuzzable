#!/usr/bin/env python3
"""
__main__.py

    Command line entry point for launching the standalone CLI executable.
"""
import typing as t
import typer

from pathlib import Path

app = typer.Typer()


@app.command()
def main(target: Path):
    """
    Framework for Automating Fuzzable Target Discovery with Static Analysis
    """
    target_path = Path(target)
    if target_path.is_file():
        pass
    elif target_path.is_dir():
        pass
    else:
        typer.echo("asd")
