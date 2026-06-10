"""
binja.py

    Fuzzable analysis support for the Binary Ninja disassembler. Can be invoked both through
    registered plugin handlers, and through a headless standalone CLI.

"""
import typing as t

import binaryninja.demangle as demangle
from binaryninja import BinaryView
from binaryninja.enums import SymbolType
from binaryninja.function import Function
from binaryninja.log import Logger
from binaryninja.plugin import BackgroundTaskThread

from ..analysis.metrics import Capability
from ..analysis.model import Function as ModelFunction
from ..analysis.model import Parameter, once
from ..analysis import AnalysisBackend, Fuzzability

log = Logger(0, "Fuzzable")

class BinjaAnalysis(AnalysisBackend):
    """Derived class to support Binary Ninja, and can be dispatched as a task from the plugin."""

    # Binary Ninja recovers types, CFGs, the call graph and variable dataflow
    capabilities = (
        Capability.NAME
        | Capability.TYPES
        | Capability.CFG
        | Capability.CALLS
        | Capability.DATAFLOW
    )

    def __init__(
        self,
        target: BinaryView,
        include_sym: list[str] = [],
        include_nontop: bool = False,
        skip_sym: list[str] = [],
        skip_stripped: bool = False,
        score_weights: list[float] | None = None,
    ):
        super().__init__(
            include_sym=include_sym,
            include_nontop=include_nontop,
            skip_sym=skip_sym,
            skip_stripped=skip_stripped,
            score_weights=score_weights,
        )
        self.view: BinaryView = target

    def __str__(self) -> str:
        return "Binary Ninja"

    def rank(self) -> Fuzzability | None:
        self.view.update_analysis_and_wait()
        ranked = super().rank()  # generic pipeline: discover -> filter -> score -> rank
        return ranked

    def yield_candidate(self) -> t.Iterator[Function]:
        """Yield each non-imported function in the view as a normalized model."""
        funcs = self.view.functions
        log.log_info(f"Starting fuzzable analysis over {len(funcs)} symbols in binary")
        for func in funcs:
            name = demangle.simplify_name_to_string(func.name)
            addr = str(hex(func.address_ranges[0].start))
            if self._is_import(func):
                self.skipped[name] = addr
                continue
            yield self._to_function(name, addr, func)

    def _to_function(self, name: str, addr: str, func: Function) -> ModelFunction:
        """Adapt a Binary Ninja function into the normalized model."""
        return ModelFunction(
            name=name,
            location=addr,
            capabilities=self.capabilities,
            is_top_level=len(func.callers) == 0,
            stripped="sub_" in name,
            parameters=self._parameters(func),
            measures={
                "taint_influence": once(lambda f=func: self._taint_influence(f)),
                "natural_loops": once(lambda f=func: self._natural_loops(f)),
                "cyclomatic_complexity": once(
                    lambda f=func: self._cyclomatic_complexity(f)
                ),
                "coverage_depth": once(lambda f=func: self._coverage_depth(f)),
            },
            raw=func,
        )

    @staticmethod
    def _is_import(func: Function) -> bool:
        """Whether a function is an imported/library symbol (not our code)."""
        return func.symbol.type in [
            SymbolType.ImportedFunctionSymbol,
            SymbolType.LibraryFunctionSymbol,
            SymbolType.ImportAddressSymbol,
            SymbolType.ImportedDataSymbol,
        ]

    def _parameters(self, func: Function) -> list[Parameter]:
        """
        Normalize Binary Ninja's recovered parameter types for the shared
        input-surface feature.
        """
        parameters: list[Parameter] = []
        for param in func.parameter_vars:
            param_type = getattr(param, "type", None)
            if param_type is None:
                parameters.append(Parameter())
                continue

            type_str = str(param_type).lower()
            points_to_bytes = False
            is_file = False
            is_integral = False
            if "*" in type_str:
                if "file" in type_str:
                    is_file = True
                elif any(
                    token in type_str
                    for token in ("char", "void", "uint8", "int8", "byte")
                ):
                    points_to_bytes = True
            elif any(token in type_str for token in ("int", "size_t", "long", "short")):
                is_integral = True

            parameters.append(
                Parameter(
                    points_to_bytes=points_to_bytes,
                    is_integral=is_integral,
                    is_file=is_file,
                )
            )
        return parameters

    def _taint_influence(self, func: Function) -> float:
        """
        Fraction of the function's MLIL instructions that reference an input-derived
        value. Binary Ninja already performs variable dataflow, so we approximate
        forward taint by counting instructions that reference any parameter variable
        (directly or through Binary Ninja's recovered variable references).
        """
        try:
            instructions = list(func.mlil.instructions)
        except Exception as err:
            log.log_debug(f"{func.name}: could not read MLIL ({err})")
            return 0.0

        total = len(instructions)
        if total == 0:
            return 0.0

        # collect the addresses of every instruction that references a parameter
        influenced_addrs: set[int] = set()
        for param in func.parameter_vars:
            try:
                for ref in func.get_mlil_var_refs(param):
                    influenced_addrs.add(ref.address)
            except Exception:
                continue

        if not influenced_addrs:
            return 0.0

        influenced = sum(1 for insn in instructions if insn.address in influenced_addrs)
        return influenced / total

    def _coverage_depth(self, target: Function) -> float:
        """Coverage depth via a DFS over the call graph: count reachable functions."""
        seen: set[str] = set()
        callstack = [target]
        depth = 0
        while callstack:
            func = callstack.pop()
            if func.name in seen:
                continue
            seen.add(func.name)
            depth += 1
            for child in func.callees:
                if child.name not in seen:
                    callstack += [child]
        return depth

    def _natural_loops(self, target: Function) -> float:
        """Loops via basic blocks present in their own dominance frontier."""
        return len([bb for bb in target.basic_blocks if bb in bb.dominance_frontier])

    def _cyclomatic_complexity(self, func: Function) -> float:
        """McCabe complexity on the basic-block graph: M = E - N + 2."""
        num_blocks = len(func.basic_blocks)
        num_edges = sum(len(b.outgoing_edges) for b in func.basic_blocks)
        return num_edges - num_blocks + 2
