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
    #table.add_column("Location", style="magenta")
    table.add_column("Fuzzability Score", style="green")
    table.add_column("Fuzz-Friendly Name?", style="green")
    table.add_column("Risky Data Sinks?", style="green")
    table.add_column("Natural Loops?", style="green")
    table.add_column("Cyclomatic Complexity", style="green")
    table.add_column("Coverage Depth", style="green")

    for row in fuzzability:
        table.add_row(row["name"], str(row["fuzz_friendly"]), str(row["sinks"]), str(row["loop"]), str(row["coverage"]))

    console = Console()
    console.print(table)
