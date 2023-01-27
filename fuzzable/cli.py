"""
cli.py

    Utilities for printing things to the UI
"""
import sys
import json
import typer
import typing as t

from rich.console import Console
from rich.table import Table

from .analysis import Fuzzability, CallScore
from .metrics import METRICS
from .log import log

from io import StringIO
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


def generate_table(target: Path, fuzzability: Fuzzability, ignore_metrics: bool):
    """Create a table from fuzzability results"""
    table = Table(
        title=f"Fuzzable Report for Target `{target}`",
        expand=True,
        safe_box=True,
    )

    # iterate over each field if flag is set, otherwise only first 3 pieces of info
    if not ignore_metrics:
        miter = METRICS
    else:
        miter = METRICS[0:3]

    for column in [metric.friendly_name for metric in miter]:
        table.add_column(column, style="magenta")

    for row in fuzzability:
        row_args = [str(getattr(row, metric.identifier)) for metric in miter]
        table.add_row(*row_args)

    return table


def print_table(
    target: Path,
    fuzzability: Fuzzability,
    skipped: t.Dict[str, str],
    ignore_metrics: bool,
    list_ignored: bool,
    table_export: bool = False,  # set by binja or another disassembler
) -> None:
    """Pretty-prints fuzzability results for the CLI"""

    table = generate_table(target, fuzzability, ignore_metrics)

    # console output is in-memory if table_export
    if table_export:
        console = Console(file=StringIO())
    else:
        console = Console(record=True)

    rprint = console.print
    rprint("\n")
    rprint(table)
    rprint("\n[bold red]ADDITIONAL METADATA[/bold red]\n")
    rprint(f"[underline]Number of Symbols Analyzed[/underline]: \t\t{len(fuzzability)}")
    rprint(f"[underline]Number of Symbols Skipped[/underline]: \t\t{len(skipped)}")
    rprint(f"[underline]Top Fuzzing Contender[/underline]: \t\t{fuzzability[0].name}\n")

    if list_ignored:
        rprint("\n[bold red]SKIPPED SYMBOLS[/bold red]\n")
        for name, loc in skipped.items():
            rprint(f"* {name} ({loc})")
        rprint("\n")

    # if argument is set, return the captured output
    if table_export:
        return console.file.getvalue()
    else:
        return None


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
