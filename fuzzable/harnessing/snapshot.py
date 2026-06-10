"""
snapshot.py

    In-process, binary-only snapshot fuzzing built on miasm's emulation engine:
        1. restores the snapshot (registers + dirtied/added pages),
        2. injects a mutated input buffer into a mapped page,
        3. runs the target function under emulation with the buffer/size in the
           calling-convention argument registers,
        4. watches for a memory-safety violation (the crash oracle).
"""

import logging
import random
from dataclasses import dataclass
from pathlib import Path

from miasm.analysis.binary import Container
from miasm.analysis.sandbox import Sandbox_Linux_x86_64
from miasm.core.locationdb import LocationDB
from miasm.jitter.csts import PAGE_READ, PAGE_WRITE

from ..log import log

# miasm loggers that emit per-call chatter (malloc stubs, syscalls, loader notes)
# during emulation. They attach their own stderr handlers and propagate to root, so
# we both raise their level and stop propagation.
_MIASM_LOGGERS = (
    "jit function call",
    "jitload.py",
    "jit_x86",
    "loader_common",
    "loader_elf",
    "elfparse",
    "peparse",
    "symbexec",
    "analysis",
    "asmblock",
)


def _quiet_miasm() -> None:
    """Silence miasm's noisy emulation loggers (it raises their level on init)."""
    for name in _MIASM_LOGGERS:
        logger = logging.getLogger(name)
        logger.setLevel(logging.ERROR)
        logger.propagate = False


# quiet at import so loader chatter during sandbox construction is suppressed too
_quiet_miasm()


def resolve_function(path: str | Path, symbol: str) -> int:
    """
    Look up a function symbol's address via miasm's loader, prefers the
    static `.symtab`, falling back to the dynamic `.dynsym`.
    """
    loc_db = LocationDB()
    with open(path, "rb") as stream:
        container = Container.from_stream(stream, loc_db)

    executable = getattr(container, "executable", None)
    if executable is None or not hasattr(executable, "getsectionbyname"):
        raise ValueError(f"cannot read symbols from `{path}`")

    for section_name in (".symtab", ".dynsym"):
        section = executable.getsectionbyname(section_name)
        symbols = getattr(section, "symbols", None) if section else None
        if not symbols:
            continue
        for sym in symbols.values():
            if (getattr(sym, "info", 0) & 0xF) != _STT_FUNC or not sym.value:
                continue
            name = sym.name
            if isinstance(name, bytes):
                name = name.decode("utf-8", "replace")
            if name == symbol:
                return sym.value

    raise ValueError(f"function symbol `{symbol}` not found in `{path}`")


# ELF symbol type for a function (st_info & 0xf)
_STT_FUNC = 2

# address at which the fuzzer-controlled input buffer is mapped
_INPUT_ADDR = 0x40000000

# integer-argument registers, in calling-convention order, per sandbox arch
_ARG_REGISTERS: dict[str, list[str]] = {
    "x86_64": ["RDI", "RSI", "RDX", "RCX", "R8", "R9"],
}


@dataclass
class Crash:
    """A memory-safety violation observed while running the target."""

    data: bytes
    size: int
    exception: int  # miasm VM exception flag (access-violation bits)
    pc: int  # instruction pointer at the fault


class SnapshotFuzzer:
    """Emulation-backed snapshot fuzzer for a single binary function target."""

    def __init__(
        self,
        target: str | Path,
        symbol: str,
        *,
        buffer_arg: int = 0,
        size_arg: int = 1,
        input_size: int = 0x8000,
        jit_type: str = "python",
    ):
        self.path = Path(target)
        self.symbol = symbol
        self.buffer_arg = buffer_arg
        self.size_arg = size_arg
        self.input_size = input_size

        self.func_addr = self._resolve_symbol(symbol)

        # load the ELF into miasm's Linux sandbox (libc/syscall stubs, real stack);
        # the python JIT backend keeps this compiler-free.
        options = Sandbox_Linux_x86_64.parser(
            description="fuzzable snapshot fuzzer"
        ).parse_args(["-j", jit_type])
        self.sandbox = Sandbox_Linux_x86_64(LocationDB(), str(self.path), options)
        self.jitter = self.sandbox.jitter
        self.arg_registers = _ARG_REGISTERS["x86_64"]

        # sandbox construction re-raises miasm's logger levels; quiet them now
        _quiet_miasm()

        # map the input region the harness writes fuzz bytes into
        self.jitter.vm.add_memory_page(
            _INPUT_ADDR,
            PAGE_READ | PAGE_WRITE,
            b"\x00" * self.input_size,
            "fuzz_input",
        )

        # capture the clean baseline state to restore before every run
        self._snapshot()

    def _resolve_symbol(self, symbol: str) -> int:
        """Look up a function symbol's address via miasm's loader (no lief)."""
        return resolve_function(self.path, symbol)

    def _snapshot(self) -> None:
        """Capture the baseline registers and memory pages."""
        self._regs = dict(self.jitter.cpu.get_gpreg())
        self._mem = {
            addr: info["data"] for addr, info in self.jitter.vm.get_all_memory().items()
        }

    def _restore(self) -> None:
        """Roll the VM back to the captured baseline."""
        # drop pages allocated during the previous run (e.g. heap from malloc)
        for addr in list(self.jitter.vm.get_all_memory()):
            if addr not in self._mem:
                try:
                    self.jitter.vm.remove_memory_page(addr)
                except Exception:
                    pass
        # rewrite baseline page contents and registers
        for addr, data in self._mem.items():
            self.jitter.vm.set_mem(addr, data)
        self.jitter.cpu.set_gpreg(self._regs)
        self.jitter.vm.set_exception(0)

    def run_once(self, data: bytes) -> Crash | None:
        """Run the target once on `data`; return a Crash on a memory violation."""
        self._restore()

        payload = data[: self.input_size]
        self.jitter.vm.set_mem(
            _INPUT_ADDR, payload + b"\x00" * (self.input_size - len(payload))
        )

        # place the buffer pointer and length in the configured argument registers
        args = [0] * (max(self.buffer_arg, self.size_arg) + 1)
        args[self.buffer_arg] = _INPUT_ADDR
        args[self.size_arg] = len(data)

        try:
            self.sandbox.call(self.func_addr, *args)
        except Exception as err:  # emulation faults surface as various exceptions
            log.debug(
                f"{self.symbol}: emulation fault on {len(data)}-byte input: {err}"
            )
            return self._crash(data)

        if self.jitter.vm.get_exception():
            return self._crash(data)
        return None

    def _crash(self, data: bytes) -> Crash:
        return Crash(
            data=data,
            size=len(data),
            exception=self.jitter.vm.get_exception(),
            pc=int(self.jitter.cpu.RIP),
        )

    def fuzz(
        self,
        iterations: int = 2000,
        seed: bytes = b"fuzzable",
        rng: random.Random | None = None,
    ) -> list[Crash]:
        """Havoc-mutate from a seed corpus and collect unique crashes."""
        rng = rng or random.Random(0)
        corpus: list[bytes] = [seed]
        crashes: list[Crash] = []
        seen: set[int] = set()

        for _ in range(iterations):
            data = self._mutate(rng.choice(corpus), rng)
            crash = self.run_once(data)
            if crash is None:
                if len(corpus) < 64 and rng.random() < 0.1:
                    corpus.append(data)
                continue
            if crash.exception not in seen:
                seen.add(crash.exception)
                crashes.append(crash)
                log.warning(
                    f"{self.symbol}: crash on {crash.size}-byte input "
                    f"(exception={hex(crash.exception)}, pc={hex(crash.pc)})"
                )

        return crashes

    @staticmethod
    def _mutate(data: bytes, rng: random.Random) -> bytes:
        """A small havoc mutator: bit/byte flips, growth, and truncation."""
        out = bytearray(data)
        for _ in range(rng.randint(1, 8)):
            choice = rng.randint(0, 3)
            if choice == 0 and out:
                out[rng.randrange(len(out))] ^= 1 << rng.randint(0, 7)
            elif choice == 1 and out:
                out[rng.randrange(len(out))] = rng.randint(0, 255)
            elif choice == 2:
                out += bytes(rng.randint(1, 512))
            elif choice == 3 and len(out) > 1:
                del out[rng.randrange(len(out)) :]
        return bytes(out)
