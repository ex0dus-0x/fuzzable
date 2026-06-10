"""
miasm.py

    Headless binary analysis backend built entirely on miasm: control-flow
    recovery, IR-level taint, and symbol enumeration all come from miasm's own
    loader and analysis engine (no external binary parser).
"""

import typing as t
from pathlib import Path

from miasm.analysis.binary import Container
from miasm.analysis.machine import Machine
from miasm.core.locationdb import LocationDB

from ..log import log
from ..analysis.metrics import Capability
from ..analysis.model import Function, once
from ..analysis import AnalysisBackend, AnalysisException

# A disassembled function: its entry address plus the recovered AsmCFG.
ParsedFunc = tuple[int, t.Any]

# ELF symbol type for a function (st_info & 0xf), used to filter the symbol table.
_STT_FUNC = 2

# Integer-argument registers per architecture (in calling-convention order). Used
# to approximate attack surface: an argument register dereferenced as memory is a
# pointer parameter, i.e. a likely input buffer. Stack-based ABIs (x86-32) are
# omitted since the surface cannot be read off registers.
ARG_REGISTERS: dict[str, set[str]] = {
    "x86_64": {"RDI", "RSI", "RDX", "RCX", "R8", "R9"},
    "aarch64l": {"X0", "X1", "X2", "X3", "X4", "X5", "X6", "X7"},
    "aarch64b": {"X0", "X1", "X2", "X3", "X4", "X5", "X6", "X7"},
    "arml": {"R0", "R1", "R2", "R3"},
    "armb": {"R0", "R1", "R2", "R3"},
}

# 32-bit sub-register aliases of the argument registers. miasm names these as
# distinct registers (EDI vs RDI), so taint seeded on the 64-bit register would
# otherwise miss 32-bit (e.g. `int`) argument accesses.
ARG_SUBREGISTERS: dict[str, dict[str, str]] = {
    "x86_64": {
        "RDI": "EDI",
        "RSI": "ESI",
        "RDX": "EDX",
        "RCX": "ECX",
        "R8": "R8D",
        "R9": "R9D",
    },
    "aarch64l": {f"X{i}": f"W{i}" for i in range(8)},
    "aarch64b": {f"X{i}": f"W{i}" for i in range(8)},
}


class MiasmAnalysis(AnalysisBackend):
    """Derived class to support headless binary analysis with miasm."""

    # a stripped binary gives a CFG, a call graph and IR for taint, but no real
    # parameter types -- so the type-dependent input_surface feature is not offered
    capabilities = (
        Capability.NAME | Capability.CFG | Capability.CALLS | Capability.DATAFLOW
    )

    def __init__(
        self,
        target: Path,
        include_sym: list[str] = [],
        include_nontop: bool = False,
        skip_sym: list[str] = [],
        skip_stripped: bool = False,
        score_weights: list[float] | None = None,
    ):
        super().__init__(
            include_sym, include_nontop, skip_sym, skip_stripped, score_weights
        )
        self.path = Path(target)

        log.debug("Setting up miasm disassembly engine")
        self.loc_db = LocationDB()
        try:
            with open(self.path, "rb") as stream:
                self.container = Container.from_stream(stream, self.loc_db)
        except Exception as err:
            raise AnalysisException(
                f"could not parse binary target `{self.path}`: {err}"
            )

        # a non-binary input (e.g. source text) parses but exposes no architecture
        if self.container.arch is None:
            raise AnalysisException(
                f"`{self.path}` is not a recognized binary (no architecture detected)"
            )

        self.machine = Machine(self.container.arch)
        self.mdis = self.machine.dis_engine(
            self.container.bin_stream, loc_db=self.loc_db
        )
        # only recover intra-function control flow; calls are resolved separately
        self.mdis.follow_call = False

        # IR lifter, reused to lift each function for forward-taint analysis
        try:
            self.lifter = self.machine.lifter_model_call(self.loc_db)
        except AttributeError:  # older miasm releases
            self.lifter = self.machine.ira(self.loc_db)

        # name -> entry address for every defined function symbol
        self.functions: dict[str, int] = self._collect_functions()
        self.addr_to_name: dict[int, str] = {
            addr: name for name, addr in self.functions.items()
        }

        # populated during run(): name -> (addr, AsmCFG), and the callgraph
        self.parsed: dict[str, ParsedFunc] = {}
        self.callees: dict[str, set[str]] = {}
        self.callers: dict[str, set[str]] = {}

    def __str__(self) -> str:
        return "miasm"

    def _collect_functions(self) -> dict[str, int]:
        """
        Enumerate defined function symbols (name -> address) from the ELF symbol
        tables parsed by miasm's own loader. The static `.symtab` is preferred; the
        dynamic `.dynsym` is also consulted so stripped-but-exported functions are
        still found.
        """
        executable = getattr(self.container, "executable", None)
        if executable is None or not hasattr(executable, "getsectionbyname"):
            log.warning("miasm could not expose a symbol table for the target")
            return {}

        functions: dict[str, int] = {}
        for section_name in (".symtab", ".dynsym"):
            try:
                section = executable.getsectionbyname(section_name)
            except Exception:
                section = None
            if section is None:
                continue

            symbols = getattr(section, "symbols", None)
            if symbols is None:
                continue
            entries = symbols.values() if hasattr(symbols, "values") else symbols
            for sym in entries:
                # filter to defined function symbols with a concrete address
                if (getattr(sym, "info", 0) & 0xF) != _STT_FUNC:
                    continue
                value = getattr(sym, "value", 0)
                if not value:
                    continue
                name = getattr(sym, "name", b"")
                if isinstance(name, bytes):
                    name = name.decode("utf-8", "replace")
                if not name:
                    continue
                functions.setdefault(name, value)

        return functions

    def yield_candidate(self) -> t.Iterator[Function]:
        """Disassemble candidate functions, build the call graph, then yield models."""
        log.info("Disassembling candidate functions and building the callgraph")
        for name, addr in self.functions.items():
            if self.skip_analysis(name):
                self.skipped[name] = hex(addr)
                continue
            try:
                asmcfg = self.mdis.dis_multiblock(addr)
            except Exception as err:
                log.warning(f"Could not disassemble {name} ({hex(addr)}): {err}")
                self.skipped[name] = hex(addr)
                continue

            self.parsed[name] = (addr, asmcfg)
            callees = self._resolve_callees(asmcfg)
            self.callees[name] = callees
            for callee in callees:
                self.callers.setdefault(callee, set()).add(name)

        for name, (addr, asmcfg) in self.parsed.items():
            yield self._to_function(name, addr, asmcfg)

    def _to_function(self, name: str, addr: int, asmcfg: t.Any) -> Function:
        """Adapt a disassembled function into the normalized model."""
        func: ParsedFunc = (addr, asmcfg)
        return Function(
            name=name,
            location=hex(addr),
            capabilities=self.capabilities,
            is_top_level=len(self.callers.get(name, set())) == 0,
            stripped="sub_" in name,
            parameters=[],  # no recovered types on a stripped binary
            measures={
                "taint_influence": once(lambda f=func: self._taint_influence(f)),
                "natural_loops": once(lambda f=func: self._natural_loops(f)),
                "cyclomatic_complexity": once(
                    lambda f=func: self._cyclomatic_complexity(f)
                ),
                "coverage_depth": once(lambda n=name: self._coverage_depth(n)),
            },
            raw=func,
        )

    def _taint_influence(self, func: ParsedFunc) -> float:
        """
        FEATURE: fraction of the function's IR operations driven by input-derived values.

        Lifts the function to miasm IR and runs a forward may-taint analysis seeded
        from the architecture's argument registers: an assignment is "tainted" when
        its source reads any tainted register or memory cell, and its destination is
        then tainted (or killed otherwise). A fixpoint over the IR CFG handles
        branches and loops. The score is ``tainted_assignments / total_assignments``.

        This needs no symbols or types, so it measures attacker influence uniformly
        across stripped binaries of any register-ABI architecture.
        """
        addr, asmcfg = func
        seed = self._taint_seed()
        if not seed:
            return 0.0

        try:
            ircfg = self.lifter.new_ircfg_from_asmcfg(asmcfg)
        except Exception as err:
            log.debug(f"taint: could not lift IR for {hex(addr)}: {err}")
            return 0.0

        entry = self.loc_db.get_offset_location(addr)
        if entry not in ircfg.blocks:
            heads = ircfg.heads()
            entry = heads[0] if heads else None

        # forward may-taint fixpoint: out[b] = transfer(union(out[preds]) (+seed at entry))
        out_state: dict[t.Any, set[str]] = {lbl: set() for lbl in ircfg.blocks}
        worklist = list(ircfg.blocks)
        while worklist:
            lbl = worklist.pop()
            # successors may reference loc_keys with no materialized IR block
            # (call returns, unresolved targets); skip those.
            if lbl not in ircfg.blocks:
                continue
            incoming = self._incoming_state(ircfg, lbl, out_state, entry, seed)
            new_out = self._transfer_block(ircfg.blocks[lbl], incoming)
            if new_out != out_state[lbl]:
                out_state[lbl] = new_out
                worklist.extend(
                    succ for succ in ircfg.successors(lbl) if succ in ircfg.blocks
                )

        # final pass: count tainted vs total assignments using converged states
        total = 0
        tainted = 0
        for lbl, irblock in ircfg.blocks.items():
            state = self._incoming_state(ircfg, lbl, out_state, entry, seed)
            for assignblk in irblock.assignblks:
                for dst, src in assignblk.items():
                    total += 1
                    tainted_src = bool(self._value_atoms(src) & state)
                    if tainted_src:
                        tainted += 1
                    self._apply_taint(dst, state, tainted_src)

        return tainted / total if total else 0.0

    def _taint_seed(self) -> set[str]:
        """Argument registers (including 32-bit sub-registers) for the target ABI."""
        arch = str(self.container.arch)
        registers = ARG_REGISTERS.get(arch, set())
        seed = set(registers)
        subregisters = ARG_SUBREGISTERS.get(arch, {})
        seed |= {subregisters[reg] for reg in registers if reg in subregisters}
        return seed

    @staticmethod
    def _incoming_state(
        ircfg: t.Any,
        lbl: t.Any,
        out_state: dict[t.Any, set[str]],
        entry: t.Any,
        seed: set[str],
    ) -> set[str]:
        """Union of predecessor out-states, plus the seed taint at the entry block."""
        state: set[str] = set()
        for pred in ircfg.predecessors(lbl):
            state |= out_state.get(pred, set())
        if lbl == entry:
            state |= seed
        return state

    def _transfer_block(self, irblock: t.Any, incoming: set[str]) -> set[str]:
        state = set(incoming)
        for assignblk in irblock.assignblks:
            for dst, src in assignblk.items():
                self._apply_taint(dst, state, bool(self._value_atoms(src) & state))
        return state

    @staticmethod
    def _value_atoms(expr: t.Any) -> set[str]:
        """
        Value-flow atoms read by an expression: register names and memory cells.
        A memory read also contributes its address registers, so dereferencing a
        tainted pointer propagates taint to the loaded value.
        """
        atoms: set[str] = set()
        todo = [expr]
        while todo:
            current = todo.pop()
            if current.is_id():
                atoms.add(current.name)
            elif current.is_mem():
                atoms.add(str(current))
                todo.append(current.ptr)
            elif current.is_op():
                todo.extend(current.args)
            elif current.is_slice():
                todo.append(current.arg)
            elif current.is_compose():
                todo.extend(current.args)
            elif current.is_cond():
                todo.extend([current.cond, current.src1, current.src2])
        return atoms

    @staticmethod
    def _apply_taint(dst: t.Any, state: set[str], tainted: bool) -> None:
        """Taint or kill the destination location of an assignment."""
        if dst.is_id():
            atom = dst.name
        elif dst.is_mem():
            atom = str(dst)
        else:
            return
        if tainted:
            state.add(atom)
        else:
            state.discard(atom)

    def _coverage_depth(self, name: str) -> float:
        """
        Functions reachable from this one by walking the call graph,
        approximating how much a fuzzer could explore from this entry point.
        """
        seen: set[str] = set()
        stack = [name]
        depth = 0
        while stack:
            current = stack.pop()
            if current in seen:
                continue
            seen.add(current)
            depth += 1
            for callee in self.callees.get(current, set()):
                if callee not in seen:
                    stack += [callee]
        return depth

    def _natural_loops(self, func: ParsedFunc) -> float:
        """Natural loops, counted as back-edges in the function CFG."""
        addr, asmcfg = func
        head = self.loc_db.get_offset_location(addr)
        if head is None or head not in set(asmcfg.nodes()):
            heads = asmcfg.heads()
            if not heads:
                return 0
            head = heads[0]
        try:
            return len(list(asmcfg.compute_back_edges(head)))
        except Exception as err:
            log.debug(f"could not compute back-edges: {err}")
            return 0

    def _cyclomatic_complexity(self, func: ParsedFunc) -> float:
        """McCabe complexity on the basic-block graph: M = E - N + 2."""
        _addr, asmcfg = func
        num_nodes = len(list(asmcfg.nodes()))
        num_edges = len(list(asmcfg.edges()))
        return num_edges - num_nodes + 2

    def _resolve_callees(self, asmcfg: t.Any) -> set[str]:
        """Collect the names of functions called within a disassembled function."""
        callees: set[str] = set()
        for block in asmcfg.blocks:
            for line in block.lines:
                if not line.is_subcall():
                    continue
                callee = self._callee_name(line)
                if callee is not None:
                    callees.add(callee)
        return callees

    def _call_target_names(self, line: t.Any) -> set[str]:
        """Resolve every symbol name a call instruction might target."""
        if not line.args:
            return set()

        dst = line.args[0]
        if dst.is_loc():
            names = set(self.loc_db.get_location_names(dst.loc_key))
            if names:
                return names
            offset = self.loc_db.get_location_offset(dst.loc_key)
            target = self.addr_to_name.get(offset)
            return {target} if target else set()

        if dst.is_int():
            target = self.addr_to_name.get(int(dst))
            return {target} if target else set()

        # indirect/computed call target we cannot resolve statically
        return set()

    def _callee_name(self, line: t.Any) -> str | None:
        """Pick a single canonical callee name, preferring a known defined function."""
        names = self._call_target_names(line)
        for name in names:
            if name in self.functions:
                return name
        return next(iter(names)) if names else None
