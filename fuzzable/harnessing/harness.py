"""
harness.py

    Turn fuzzable's static analysis into a ready-to-run snapshot-fuzzing campaign.

    The analysis answers the questions a snapshot fuzzer needs by hand: which
    function to target, its address, and which registers carry the input buffer and
    its length. We capture those in an engine-agnostic ``SnapshotSpec`` and emit a
    complete campaign bundle (config + harness driver + scripts + seeds) for a fast
    native engine -- currently LibAFL-QEMU persistent mode.

    All generated files use ``string.Template`` ($placeholders), which cannot
    collide with the C/Python/TOML braces in the templates -- structurally avoiding
    the brace bug that made the previous str.replace generator emit broken code.
"""

import string
from dataclasses import dataclass
from pathlib import Path

from miasm.analysis.binary import Container
from miasm.core.locationdb import LocationDB

from ..log import log
from .snapshot import resolve_function

# memory region the harness maps for fuzzer-controlled input
_INPUT_ADDR = 0x40000000

SUPPORTED_ENGINES = ("libafl-qemu",)


def default_registers(arch: str) -> tuple[str, str]:
    """
    (data-pointer, length) argument registers for an architecture's calling
    convention. Matches leniently so both miasm arch ids ("aarch64l") and
    disassembler names ("aarch64", "x86_64") resolve.
    """
    name = arch.lower()
    if "aarch64" in name or "arm64" in name:
        return ("x0", "x1")
    if "arm" in name:
        return ("r0", "r1")
    # x86-64 / amd64 (and a lenient default for unrecognized register ABIs)
    return ("rdi", "rsi")


@dataclass
class SnapshotSpec:
    """Everything a snapshot fuzzer needs to drive one function, from analysis."""

    binary: Path
    symbol: str
    arch: str
    func_addr: int
    data_reg: str
    size_reg: str
    input_addr: int = _INPUT_ADDR
    max_input_size: int = 0x1000

    @property
    def func_addr_hex(self) -> str:
        return hex(self.func_addr)

    @property
    def input_addr_hex(self) -> str:
        return hex(self.input_addr)


def _detect_arch(path: Path) -> str:
    loc_db = LocationDB()
    with open(path, "rb") as stream:
        container = Container.from_stream(stream, loc_db)
    return str(container.arch)


def select_top_target(path: str | Path) -> str:
    """Pick the highest-ranked fuzzable function via the binary analysis backend."""
    from ..backend.miasm import MiasmAnalysis

    results = MiasmAnalysis(path, include_nontop=True).rank()
    if not results:
        raise ValueError(f"no analyzable functions found in `{path}`")
    return results[0].name


def build_spec(
    binary: str | Path,
    symbol: str | None = None,
    *,
    data_reg: str | None = None,
    size_reg: str | None = None,
    max_input_size: int = 0x1000,
) -> SnapshotSpec:
    """Derive a SnapshotSpec from a binary, auto-selecting the target if needed."""
    binary = Path(binary)
    arch = _detect_arch(binary)

    if symbol is None:
        symbol = select_top_target(binary)
        log.info(f"Auto-selected top fuzzable target: {symbol}")

    func_addr = resolve_function(binary, symbol)

    default_data, default_size = default_registers(arch)

    return SnapshotSpec(
        binary=binary,
        symbol=symbol,
        arch=arch,
        func_addr=func_addr,
        data_reg=data_reg or default_data,
        size_reg=size_reg or default_size,
        max_input_size=max_input_size,
    )


def emit_bundle(
    spec: SnapshotSpec, out_dir: str | Path, *, engine: str = "libafl-qemu"
) -> list[Path]:
    """Write the campaign bundle for `spec` to `out_dir`; returns written paths."""
    if engine not in SUPPORTED_ENGINES:
        raise ValueError(
            f"unsupported engine `{engine}`; choose from {SUPPORTED_ENGINES}"
        )

    out_dir = Path(out_dir)
    (out_dir / "seeds").mkdir(parents=True, exist_ok=True)

    mapping = {
        "binary_name": spec.binary.name,
        "symbol": spec.symbol,
        "arch": spec.arch,
        "func_addr": spec.func_addr_hex,
        "input_addr": spec.input_addr_hex,
        "data_reg": spec.data_reg,
        "size_reg": spec.size_reg,
        "max_input_size": str(spec.max_input_size),
    }

    written: list[Path] = []

    def write(name: str, template: string.Template, executable: bool = False) -> None:
        path = out_dir / name
        path.write_text(template.substitute(mapping))
        if executable:
            path.chmod(0o755)
        written.append(path)

    write("snapshot.toml", _SNAPSHOT_TOML)
    write("fuzzer.py", _FUZZER_PY)
    write("build.sh", _BUILD_SH, executable=True)
    write("run.sh", _RUN_SH, executable=True)
    write("README.md", _README_MD)

    # a minimal starter seed and dictionary
    seed = out_dir / "seeds" / "seed_0"
    seed.write_bytes(b"fuzzable\n")
    written.append(seed)
    dict_path = out_dir / "dict.txt"
    dict_path.write_text('# add tokens here, e.g.  magic="\\x7fELF"\n')
    written.append(dict_path)

    return written


_SNAPSHOT_TOML = string.Template(
    """# fuzzable snapshot spec (engine-agnostic source of truth)
binary = "$binary_name"
symbol = "$symbol"
arch = "$arch"
func_addr = "$func_addr"      # snapshot/breakpoint entry point
input_addr = "$input_addr"    # where fuzz bytes are written
data_reg = "$data_reg"        # register holding the input pointer
size_reg = "$size_reg"        # register holding the input length
max_input_size = $max_input_size
"""
)


_FUZZER_PY = string.Template(
    '''#!/usr/bin/env python3
"""
Auto-generated by fuzzable.

LibAFL-QEMU persistent snapshot fuzzer for `$symbol` in `$binary_name`.
Snapshot entry: $func_addr   data=$data_reg   size=$size_reg

This targets the LibAFL QEMU Python bindings (pylibafl / QemuBytesCoverageSugar);
depending on your installed LibAFL version some API names may differ. The target
details below are mirrored in snapshot.toml (the engine-agnostic source of truth).
"""
from pathlib import Path

from pylibafl import qemu
from pylibafl.sugar import QemuBytesCoverageSugar

# snapshot spec (see snapshot.toml)
FUNC_ADDR = $func_addr
INPUT_ADDR = $input_addr
MAX_LEN = $max_input_size
DATA_REG = "$data_reg"
SIZE_REG = "$size_reg"

emu = qemu.Qemu(["./$binary_name"], [])

# run to the target, then snapshot at its entry (persistent loop boundary)
emu.set_breakpoint(FUNC_ADDR)
emu.run()
return_addr = emu.read_return_address()
emu.remove_breakpoint(FUNC_ADDR)
emu.set_breakpoint(return_addr)
snapshot = emu.create_fast_snapshot()


def harness(payload: bytes) -> None:
    buf = bytes(payload)[:MAX_LEN]
    emu.write_mem(INPUT_ADDR, buf)
    emu.write_reg(DATA_REG, INPUT_ADDR)
    emu.write_reg(SIZE_REG, len(buf))
    emu.run()
    emu.restore_fast_snapshot(snapshot)


if __name__ == "__main__":
    fuzzer = QemuBytesCoverageSugar(
        input_dirs=[Path("seeds")],
        output_dir=Path("out"),
        broker_port=1337,
        cores=[0],
        harness=harness,
    )
    fuzzer.run()
'''
)


_BUILD_SH = string.Template(
    """#!/usr/bin/env bash
set -euo pipefail

# Build the LibAFL QEMU Python bindings (pylibafl). Adjust to your checkout:
#
#   git clone https://github.com/AFLplusplus/LibAFL
#   cd LibAFL/bindings/pylibafl
#   maturin develop --release
#
# Then run ./run.sh from this directory.
echo "Set up pylibafl (see comments above and README.md), then ./run.sh"
"""
)


_RUN_SH = string.Template(
    """#!/usr/bin/env bash
set -euo pipefail
exec python3 fuzzer.py
"""
)


_README_MD = string.Template(
    """# Snapshot fuzzing campaign: `$symbol`

Auto-generated by fuzzable from `$binary_name` ($arch).

## Inferred snapshot spec
| field | value |
|-------|-------|
| function | `$symbol` |
| entry address | `$func_addr` |
| input pointer register | `$data_reg` |
| input length register | `$size_reg` |
| input mapped at | `$input_addr` |
| max input size | `$max_input_size` |

The source of truth is `snapshot.toml`; `fuzzer.py` reads it, so re-targeting only
means editing that file.

## Run
1. `./build.sh` — set up the LibAFL QEMU Python bindings.
2. drop starter inputs in `seeds/` and tokens in `dict.txt`.
3. `./run.sh` — launch the persistent, coverage-guided QEMU snapshot campaign.

## Caveats
- The argument registers are calling-convention defaults for `$arch`. If `$symbol`
  takes the buffer/length in different positions, edit `data_reg`/`size_reg` in
  `snapshot.toml`.
- `fuzzer.py` targets the pylibafl QEMU API; adjust glue to your LibAFL version.
"""
)
