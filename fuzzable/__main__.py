#!/usr/bin/env python3
import json
import logging
import sys
import typing as t
from io import StringIO
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from fuzzable.analysis import AnalysisBackend, Fuzzability
from fuzzable.log import log
from fuzzable.analysis.metrics import METRIC_IDS, METRICS

ERROR_START = click.style("fuzzable error:", fg="white", bg="red")


def error(string: str) -> t.NoReturn:
    """Pretty-prints an error message and exits"""
    exception = click.style(string, fg="red")
    click.echo(f"{ERROR_START} {exception}")
    sys.exit(1)


def print_table(
    target: Path,
    fuzzability: Fuzzability,
    skipped: dict[str, str],
    ignore_metrics: bool,
    list_ignored: bool,
    table_export: bool = False,  # set by binja or another disassembler
) -> None:
    """Pretty-prints fuzzability results for the CLI"""

    table = Table(
        title=f"Fuzzable Report for Target `{target}`",
        expand=True,
        safe_box=True,
    )

    # always show identity + score; include per-feature columns unless suppressed
    columns = ["Function Signature", "Location", "Fuzzability Score"]
    feature_columns = [] if ignore_metrics else [f.label for f in METRICS]
    for column in columns + feature_columns:
        table.add_column(column, style="magenta")

    for row in fuzzability:
        cells = [str(row.name), str(row.loc), str(row.score)]
        if not ignore_metrics:
            cells += [str(row.features.get(f.id, "")) for f in METRICS]
        table.add_row(*cells)

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

@click.group(
    help="Fuzz Target Discovery and Harnesser Tool",
    context_settings=dict(help_option_names=["-h", "--help"]),
    no_args_is_help=True,
)
@click.option(
    "-v",
    "--verbosity",
    default=0,
    type=int,
    help="Sets logging level (2 = debug, 1 = info, 0 = output).",
)
def app(verbosity: int) -> None:
    """Handles global flags for all commands."""
    if verbosity == 1:
        log.setLevel(logging.INFO)
    elif verbosity == 2:
        log.setLevel(logging.DEBUG)


@app.command()
@click.argument("target", type=click.Path(path_type=Path))
@click.option(
    "-b",
    "--backend",
    "backend",
    type=click.Choice(["miasm", "ghidra", "binja"]),
    default="miasm",
    help="Disassembly backend to help with analysis"
)
@click.option(
    "--list-ignored",
    is_flag=True,
    default=False,
    help="List filtered functions not considered for ranking.",
)
@click.option(
    "--include-sym",
    default=None,
    help="Comma-separated list of functions that must be included for ranking.",
)
@click.option(
    "--include-nontop",
    is_flag=True,
    default=False,
    help="Include non-toplevel functions in ranking (these are initial filtered by default).",
)
@click.option(
    "--skip-sym",
    default=None,
    help="Comma-seperated list of functions to exclude from ranking.",
)
@click.option(
    "--skip-stripped",
    is_flag=True,
    default=False,
    help="Ignore stripped functions from analysis",
)
@click.option(
    "--ignore-metrics/--no-ignore-metrics",
    default=True,
    help="Include individual metrics' scores for each ranked function.",
)
@click.option(
    "-w",
    "--score-weights",
    default=None,
    help="Comma-seperated list of custom metric weights used during MCDA.",
)
@click.option(
    "-j",
    "--json",
    is_flag=True,
    default=False,
    help="Output rankings in JSON.",
)
def rank(
    target: Path,
    backend: str,
    list_ignored: bool,
    include_sym: str | None,
    include_nontop: bool,
    skip_sym: str | None,
    skip_stripped: bool,
    ignore_metrics: bool,
    score_weights: str | None,
    json: bool,
):
    """
    Rank the best fuzzable target functions on a target binary.
    """
    if not target.is_file() and not target.is_dir():
        error(f"Target path `{target}` does not exist.")

    # parse custom weights and run checks; when omitted, leave as None so the
    # ranker derives objective entropy weights from the analyzed functions.
    if score_weights:
        log.debug("Reconfiguring score weights for MCDA")
        score_weights = [float(weight) for weight in score_weights.split(",")]
        num_weights = len(METRIC_IDS)
        if len(score_weights) != num_weights:
            error(f"--score-weights must contain {num_weights}")

        if sum(score_weights) != 1.0:
            error("--score-weights must sum up to 1.0")
    else:
        score_weights = None

    # parse symbols to explicitly include for analysis
    if include_sym:
        include_sym = [sym for sym in include_sym.split(",")]
        if len(include_sym) == 0:
            error("--include-sym must include at least one valid function symbol")

        log.debug(f"Parsed symbols to explicitly include for analysis {include_sym}")
    else:
        include_sym = []

    # parse symbols to explicitly exclude from analysis
    if skip_sym:
        skip_sym = [sym for sym in skip_sym.split(",")]
        if len(skip_sym) == 0:
            error("--skip-sym must specify a valid function symbol")

        log.debug(f"Parsed symbols to explicitly include for analysis {skip_sym}")
    else:
        skip_sym = []

    # check if overlapping symbols
    if set(skip_sym) & set(include_sym):
        error("Cannot have same symbols in both --include-sym and --skip-sym.")

    log.info(f"Running fuzzability analysis on {target}")

    # Prioritize loading binja as a backend; this will not work if the license is
    # personal/student, so fall back to miasm.
    back: AnalysisBackend
    if backend == "miasm":
        from fuzzable.analysis import AnalysisException

        try:
            from fuzzable.backend.miasm import MiasmAnalysis

            back = MiasmAnalysis(
                target,
                include_sym=include_sym,
                include_nontop=include_nontop,
                skip_sym=skip_sym,
                skip_stripped=skip_stripped,
                score_weights=score_weights,
            )
        except (ModuleNotFoundError, AnalysisException) as err:
            error(f"miasm failed on {target}. Reason: {err}")

    elif backend == "binja":
        import sys

        sys.tracebacklimit = 0

        from binaryninja.binaryview import BinaryViewType

        bv = BinaryViewType.get_view_of_file(target)
        bv.update_analysis_and_wait()

        from fuzzable.backend.binja import BinjaAnalysis

        back = BinjaAnalysis(
            bv,
            include_sym=include_sym,
            include_nontop=include_nontop,
            skip_sym=skip_sym,
            skip_stripped=skip_stripped,
            score_weights=score_weights,
        )

    elif backend == "ghidra":
        raise NotImplementedError

    log.info(f"Running fuzzable analysis with the {str(back)} analyzer")
    results = back.rank()
    if json:
        click.echo(json.dumps([res.asdict() for res in results]))
    else:
        print_table(target, results, back.skipped, ignore_metrics, list_ignored)


@app.command("snapshot-fuzz")
@click.argument("target", type=click.Path(path_type=Path, exists=True))
@click.option(
    "-n",
    "--symbol-name",
    "symbol_name",
    default=None,
    help="Function symbol to snapshot-fuzz. If omitted, the top-ranked fuzzable "
    "function is used.",
)
@click.option(
    "--iterations", default=2000, type=int, help="Number of fuzzing iterations."
)
@click.option(
    "--buffer-arg",
    default=0,
    type=int,
    help="Zero-based index of the buffer-pointer argument.",
)
@click.option(
    "--size-arg",
    default=1,
    type=int,
    help="Zero-based index of the buffer-length argument.",
)
@click.option(
    "--crash-dir",
    type=click.Path(path_type=Path),
    default=None,
    help="Directory to write crashing inputs to.",
)
def snapshot_fuzz(
    target: Path,
    symbol_name: str | None,
    iterations: int,
    buffer_arg: int,
    size_arg: int,
    crash_dir: Path | None,
):
    """
    Dumb binary-only snapshot fuzzing with miasm-based emulation.
    """
    from fuzzable.harnessing.harness import select_top_target
    from fuzzable.harnessing.snapshot import SnapshotFuzzer

    # default to the highest-ranked fuzzable function when no symbol is given
    if symbol_name is None:
        try:
            symbol_name = select_top_target(target)
        except ValueError as err:
            error(str(err))
        log.info(f"No symbol given; selected top-ranked target `{symbol_name}`")

    try:
        fuzzer = SnapshotFuzzer(
            target, symbol_name, buffer_arg=buffer_arg, size_arg=size_arg
        )
    except ValueError as err:
        error(str(err))

    log.info(f"Snapshot-fuzzing `{symbol_name}` in `{target}` for {iterations} iters")
    crashes = fuzzer.fuzz(iterations=iterations)

    if not crashes:
        log.info("No crashes found.")
        return

    error_start = click.style("CRASHES", fg="white", bg="red")
    click.echo(f"\n{error_start} {len(crashes)} unique memory-safety violation(s):\n")
    for index, crash in enumerate(crashes):
        click.echo(
            f"  #{index} size={crash.size} pc={hex(crash.pc)} "
            f"exception={hex(crash.exception)}"
        )
        if crash_dir is not None:
            crash_dir.mkdir(parents=True, exist_ok=True)
            out = crash_dir / f"crash_{index}_{crash.size}"
            out.write_bytes(crash.data)
            click.echo(f"     written to {out}")


@app.command("harness")
@click.argument("target", type=click.Path(path_type=Path, exists=True))
@click.option(
    "-n",
    "--symbol-name",
    "symbol_name",
    default=None,
    help="Target function symbol. If omitted, the top-ranked fuzzable function is used.",
)
@click.option(
    "--engine",
    type=click.Choice(["libafl-qemu"]),
    default="libafl-qemu",
    help="Snapshot-fuzzing engine the bundle targets.",
)
@click.option(
    "-o",
    "--out-dir",
    type=click.Path(path_type=Path),
    default=None,
    help="Output directory for the campaign bundle (default: <symbol>_harness).",
)
@click.option("--data-reg", default=None, help="Override the input-pointer register.")
@click.option("--size-reg", default=None, help="Override the input-length register.")
@click.option(
    "--max-len", default=0x1000, type=int, help="Maximum injected input size."
)
def harness(
    target: Path,
    symbol_name: str | None,
    engine: str,
    out_dir: Path | None,
    data_reg: str | None,
    size_reg: str | None,
    max_len: int,
):
    """
    Generate a ready-to-run snapshot-fuzzing campaign bundle from static analysis.

    Derives the target's address and input/length registers and emits a config,
    harness driver, build/run scripts, seeds, and a dictionary for the chosen
    engine (LibAFL-QEMU). Requires no source and no symbol export.
    """
    from fuzzable.harnessing.harness import build_spec, emit_bundle

    try:
        spec = build_spec(
            target,
            symbol=symbol_name,
            data_reg=data_reg,
            size_reg=size_reg,
            max_input_size=max_len,
        )
    except ValueError as err:
        error(str(err))

    destination = out_dir or Path(f"{spec.symbol}_harness")
    files = emit_bundle(spec, destination, engine=engine)

    click.echo(
        f"\nGenerated {engine} campaign for "
        + click.style(spec.symbol, fg="green")
        + f" @ {spec.func_addr_hex} "
        + f"({spec.data_reg}=buffer, {spec.size_reg}=size)\n"
    )
    click.echo(f"  bundle: {destination}/")
    for path in files:
        click.echo(f"    - {path.relative_to(destination)}")
    click.echo(f"\n  next: cd {destination} && ./build.sh && ./run.sh")


if __name__ == "__main__":
    app()
