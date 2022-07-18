"""
cli.py

    Utilities for printing things to the UI
"""
import sys
import typer

from rich.console import Console
from rich.table import Table

from .analysis import Fuzzability

from pathlib import Path

ERROR_START = typer.style(
    "fuzzable error:",
    fg=typer.colors.WHITE,
    bg=typer.colors.RED,
)

COLUMNS = [
    "Function Signature",
    # "Location",
    "Fuzzability Score",
    "Fuzz-Friendly Name",
    "Risky Data Sinks",
    "Natural Loops",
    "Cyclomatic Complexity",
    "Coverage Depth",
]


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

    for column in COLUMNS:
        table.add_column(column, style="magenta")

    for row in fuzzability:
        table.add_row(
            row.name,
            str(row.score),
            str(row.fuzz_friendly),
            str(row.risky_sinks),
            str(row.natural_loops),
            str(row.cyclomatic_complexity),
            str(row.coverage_depth),
        )

    console = Console()
    console.print(table)
