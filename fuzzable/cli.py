"""
cli.py

    Utilities for printing things to the UI
"""
import sys
import typer

from rich.console import Console
from rich.table import Table

from fuzzable.analysis import Fuzzability

from pathlib import Path

ERROR_START = typer.style(
    "fuzzable error:",
    fg=typer.colors.WHITE,
    bg=typer.colors.RED,
)


def error(string: str) -> None:
    """Pretty-prints an error message and exits"""
    exception = typer.style(
        string,
        fg=typer.colors.RED,
    )
    typer.echo(f"{ERROR_START} {exception}")
    sys.exit(1)


def print_table(target: Path, fuzzability: Fuzzability) -> None:
    print("\n")
    table = Table(title=f"Fuzzable Report for Target `{target}`")

    table.add_column("Function Signature", style="magenta")
    table.add_column("Location", style="magenta")
    table.add_column("Fuzzability Score", style="green")
    table.add_column("Fuzz-Friendly Name?", style="green")
    table.add_column("Risky Data Sinks?", style="green")
    table.add_column("Natural Loops?", style="green")
    table.add_column("Cyclomatic Complexity", style="green")
    table.add_column("Coverage Depth", style="green")

    table.add_row("Dec 20, 2019", "Star Wars: The Rise of Skywalker", "$952,110,690")
    table.add_row("May 25, 2018", "Solo: A Star Wars Story", "$393,151,347")
    table.add_row("Dec 15, 2017", "Star Wars Ep. V111: The Last Jedi", "$1,332,539,889")
    table.add_row("Dec 16, 2016", "Rogue One: A Star Wars Story", "$1,332,439,889")

    console = Console()
    console.print(table)
