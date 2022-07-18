#!/usr/bin/env python3
"""
__main__.py

    Command line entry point for launching the standalone CLI executable.
"""
import os
import typing as t
import typer
import lief
import logging
from rich.logging import RichHandler

from rich import print
from fuzzable import generate
from fuzzable.config import SOURCE_FILE_EXTS
from fuzzable.cli import print_table, error
from fuzzable.analysis import AnalysisBackend, AnalysisMode
from fuzzable.analysis.ast import AstAnalysis
from fuzzable.analysis.angr import AngrAnalysis

from pathlib import Path

FORMAT = "%(message)s"
logging.basicConfig(
    level="NOTSET", format=FORMAT, datefmt="[%X]", handlers=[RichHandler()]
)
log = logging.getLogger("fuzzable")
log.setLevel(logging.INFO)


app = typer.Typer(
    help="Framework for Automating Fuzzable Target Discovery with Static Analysis"
)


@app.command()
def analyze(
    target: Path,
    mode: t.Optional[str] = typer.Option(
        "recommend",
        help="Analysis mode to run under (either `recommend` or `rank`, default is `recommend`)."
        "See docs for more details about which to select.",
    ),
    out_csv: t.Optional[str] = typer.Option(
        None,
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

    log.info(f"Starting fuzzable on {target}")
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
        except Exception:
            import angr

            log.warning(
                f"Cannot load Binary Ninja as a backend. Attempting to load angr instead."
            )
            try:
                proj = angr.Project(target, load_options={"auto_load_libs": False})
                analyzer = AngrAnalysis(proj, mode)
            except Exception:
                error(
                    f"Unsupported file type `{target.suffix}`. Must be either a binary or a C/C++ source"
                )

    log.info(f"Running fuzzable analysis with the {str(analyzer)} analyzer")
    print_table(target, analyzer.run())


def run_on_workspace(
    target: Path, mode: AnalysisMode, out_csv: t.Optional[Path]
) -> None:
    """
    Given a workspace, recursively iterate and parse out all of the source code files
    that are present. This is not currently supported on workspaces of binaries/libraries.
    """
    source_files = []
    for subdir, _, files in os.walk(target):
        for file in files:
            if Path(file).suffix in SOURCE_FILE_EXTS:
                log.info(f"Adding {file} to set of source code to analyze")
                source_files += [Path(os.path.join(subdir, file))]

    if len(source_files) == 0:
        error(
            "No C/C++ source code found in the workspace. fuzzable currently does not support parsing on workspaces with multiple binaries."
        )

    analyzer = AstAnalysis(source_files, mode)
    log.info(f"Running fuzzable analysis with the {str(analyzer)} analyzer")
    print_table(target, analyzer.run())


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


# TOOD list-functions
# TODO generate-callgraph
# TODO reference-cve
