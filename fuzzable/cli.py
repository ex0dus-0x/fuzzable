"""
cli.py

    Utilities for printing things to the UI
"""
import sys
import json
import typer
import typing as t

from rich import print
from rich.console import Console
from rich.table import Table

from .analysis import Fuzzability
from .log import log

from pathlib import Path

ERROR_START = typer.style(
    "fuzzable error:",
    fg=typer.colors.WHITE,
    bg=typer.colors.RED,
)

COLUMNS = [
    "Function Signature",
    "Location",
    "Fuzzability Score",
    "Fuzz-Friendly Name",
    "Risky Data Sinks",
    "Natural Loops",
    "Cyclomatic Complexity",
    "Coverage Depth",
]

# TODO: merge with the one above
CSV_HEADER = '"name", "loc, "fuzz_friendly", "risky_sinks", "natural_loops", "cyc_complex", "cov_depth", "fuzzability"\n'


def error(string: str) -> None:
    """Pretty-prints an error message and exits"""
    exception = typer.style(
        string,
        fg=typer.colors.RED,
    )
    print(f"{ERROR_START} {exception}")
    sys.exit(1)


def print_table(
    target: Path,
    fuzzability: Fuzzability,
    skipped: t.Dict[str, str],
    list_ignored: bool,
) -> None:
    """Pretty-prints fuzzability results for the CLI"""
    table = Table(title=f"\nFuzzable Report for Target `{target}`")
    for column in COLUMNS:
        table.add_column(column, style="magenta")

    for row in fuzzability:
        table.add_row(
            row.name,
            row.loc,
            str(row.score),
            str(row.fuzz_friendly),
            str(row.risky_sinks),
            str(row.natural_loops),
            str(row.cyclomatic_complexity),
            str(row.coverage_depth),
        )

    console = Console()
    console.print(table)

    print("\n[bold red]ADDITIONAL METADATA[/bold red]\n")
    print(f"[underline]Number of Symbols Analyzed[/underline]: \t\t{len(fuzzability)}")
    print(f"[underline]Number of Symbols Skipped[/underline]: \t\t{len(skipped)}")
    print(f"[underline]Top Fuzzing Contender[/underline]: \t\t{fuzzability[0].name}\n")

    if list_ignored:
        print("\n[bold red]SKIPPED SYMBOLS[/bold red]\n")
        for name, loc in skipped.items():
            print(f"{name}\t\t{loc}")
        print("\n")


def export_results(export, results) -> None:
    writer = open(export, "w")
    ext = export.suffix
    if ext == ".json":
        writer.write(json.dumps([res.asdict() for res in results]))
    elif ext == ".csv":
        writer.write(CSV_HEADER.replace('"', ""))
        for res in results:
            writer.write(res.csv_row)
    elif ext == ".md":
        pass

    log.info(f"Written fuzzability results to `{export}`!")
    writer.close()
