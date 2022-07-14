#!/usr/bin/env python3
"""
__main__.py

    Command line entry point for launching the standalone CLI executable.
"""
import sys
import typing as t
import typer
import lief

from rich import print
from rich.console import Console
from rich.table import Table

from fuzzable import generate
from fuzzable.analysis import AnalysisBackend, AnalysisMode
from fuzzable.analysis.ast import AstAnalysis
from fuzzable.analysis.angr import AngrAnalysis

from pathlib import Path

# Supported source code paths
SOURCE_FILE_EXTS = [".c", ".cpp", ".cc", ".h", ".hpp"]

app = typer.Typer(
    help="Framework for Automating Fuzzable Target Discovery with Static Analysis"
)


def error(string: str) -> None:
    exception = typer.style(
        string,
        fg=typer.colors.WHITE,
        bg=typer.colors.RED,
    )
    typer.echo(exception)
    sys.exit(1)


@app.command()
def analyze(
    target: Path,
    mode: t.Optional[str] = typer.Option(
        "recommend",
        help="Analysis mode to run under (either `recommend` or `rank`, default is `recommend`)."
        "See docs for more details about which to select.",
    ),
    rec_export: t.Optional[bool] = typer.Option(
        False,
        help="If `--mode=recommend,` automatically attempt to generate harnesses for every candidate.",
    ),
    out_csv: t.Optional[str] = typer.Option(
        "temp.csv",
        help="Export the analysis as a CSV to a path (default is `temp.csv`).",
    ),
):
    """
    Run fuzzable analysis on a single or workspace of C/C++ source files, or a binary.
    """
    try:
        mode = AnalysisMode[mode.upper()]
    except Exception:
        return None

    if target.is_file():
        run_on_file(target, mode, out_csv)
    elif target.is_dir():
        run_on_workspace(target, mode, out_csv)
    else:
        error(f"Target path `{target}` does not exist")


def run_on_file(target: Path, mode: AnalysisMode, out_csv: t.Optional[Path]) -> None:
    """Runs analysis on a single source code file or binary file."""
    analyzer: t.TypeVar[AnalysisBackend]
    if target.suffix in SOURCE_FILE_EXTS:
        analyzer = AstAnalysis([target], mode)
    else:

        # prioritize loading binja as a backend, this may not
        # work if the license is personal/student.
        try:
            from binaryninja.binaryview import BinaryViewType
            from fuzzable.analysis.binja import BinjaAnalysis

            bv = BinaryViewType.get_view_of_file(target)
            bv.update_analysis_and_wait()
            analyzer = BinjaAnalysis(bv, mode, headless=True)

        # didn't work, try to load angr as a fallback instead
        # TODO: angr support
        except Exception:
            import angr

            typer.echo(
                f"Cannot load Binary Ninja as a backend. Attempting to load angr instead."
            )
            proj = angr.Project(target, load_options={"auto_load_libs": False})
            analyzer = AngrAnalysis(proj, mode)
        else:
            error(
                f"Unsupported file type `{target.suffix}`. Must be either a binary or a C/C++ source"
            )

    typer.echo(f"Running fuzzable analysis with {str(analyzer)} analyzer")
    #fuzzability = analyzer.run()
    #print(fuzzability)

    table = Table(title=f"Fuzzable Report for Target `{target}`")

    table.add_column("Rank", justify="right", style="cyan", no_wrap=True)
    table.add_column("Function Signature", style="magenta")
    table.add_column("Fuzzability Score", justify="right", style="green")

    table.add_row("Dec 20, 2019", "Star Wars: The Rise of Skywalker", "$952,110,690")
    table.add_row("May 25, 2018", "Solo: A Star Wars Story", "$393,151,347")
    table.add_row("Dec 15, 2017", "Star Wars Ep. V111: The Last Jedi", "$1,332,539,889")
    table.add_row("Dec 16, 2016", "Rogue One: A Star Wars Story", "$1,332,439,889")

    console = Console()
    console.print(table)


def run_on_workspace(target: Path, mode: AnalysisMode, out_csv: t.Optional[Path]) -> None:
    """
    Given a workspace, recursively iterate and parse out all of the source code files
    that are present. This is not currently supported on workspaces of binaries/libraries.
    """
    source_files = []
    for file in target.iterdir():
        if file.suffix in SOURCE_FILE_EXTS:
            source_files += [file]

    if len(source_files) == 0:
        error(
            "No C/C++ source code found in the workspace. fuzzable currently does not support parsing on workspaces with multiple binaries."
        )

    analyzer = AstAnalysis(source_files, mode)
    typer.echo(f"Running fuzzable analysis with {str(analyzer)} analyzer")
    fuzzability = analyzer.run()
    print(fuzzability)


@app.command()
def create_harness(
    target: Path,
    symbol_name: t.List[str] = typer.Option(
        [], help="Names of function symbol to create a fuzzing harness to target."
    ),
    out_so_name: str = typer.Option(
        "", help="Specify to set output `.so` of a transformed ELF binary."
    ),
    file_fuzzing: bool = typer.Option(
        False,
        help="If enabled, will generate a harness that takes a filename parameter instead of reading from STDIN.",
    ),
    libfuzzer: bool = typer.Option(
        False,
        help="If enabled, will set the flag that compiles the harness as a libFuzzer harness instead of for AFL.",
    ),
):
    """Synthesize a AFL++/libFuzzer harness for a given symbol in a target."""

    # if a binary, check if executable or library. if executable, use LIEF to
    # copy, export the symbol and transform to shared object.
    binary = lief.parse(target)
    if binary is not None:
        output = generate.transform_elf_to_so(target, binary, symbol_name, out_so_name)

    # if source code, use the generic library
    generate.generate_harness(target, file_fuzzing, libfuzzer)
    print(target, symbol_name)
