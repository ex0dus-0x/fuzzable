"""
cli.py

    Utilities for printing things to the UI
"""
import sys
import json
import typer
import typing as t

from rich import print as rprint
from rich.console import Console
from rich.table import Table

from .analysis import Fuzzability, CallScore
from .metrics import METRICS
from .log import log

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


def print_table(
    target: Path,
    fuzzability: Fuzzability,
    skipped: t.Dict[str, str],
    list_ignored: bool,
) -> None:
    """Pretty-prints fuzzability results for the CLI"""
    table = Table(title=f"\nFuzzable Report for Target `{target}`")
    for column in [metric.friendly_name for metric in METRICS]:
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

    rprint("\n[bold red]ADDITIONAL METADATA[/bold red]\n")
    rprint(f"[underline]Number of Symbols Analyzed[/underline]: \t\t{len(fuzzability)}")
    rprint(f"[underline]Number of Symbols Skipped[/underline]: \t\t{len(skipped)}")
    rprint(f"[underline]Top Fuzzing Contender[/underline]: \t\t{fuzzability[0].name}\n")

    if list_ignored:
        rprint("\n[bold red]SKIPPED SYMBOLS[/bold red]\n")
        for name, loc in skipped.items():
            rprint(f"{name}\t\t{loc}")
        rprint("\n")


def export_results(export: Path, results: t.List[CallScore]) -> None:
    """Given a file format and generated results, write to path."""
    writer = open(export, "w")
    ext = export.suffix
    if ext == ".json":
        writer.write(json.dumps([res.asdict() for res in results]))
    elif ext == ".csv":
        csv_header = ",".join([metric.identifier for metric in METRICS])
        writer.write(csv_header + "\n")
        for res in results:
            writer.write(res.csv_row)
    elif ext == ".md":
        pass

    log.info(f"Written fuzzability results to `{export}`!")
    writer.close()
