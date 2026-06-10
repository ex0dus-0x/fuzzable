"""
ghidra.py
"""

import typing as t
from ..log import log
from ..analysis.metrics import Capability
from ..analysis.model import Function, Parameter, once
from ..analysis import AnalysisBackend, AnalysisException

class GhidraAnalysis(AnalysisBackend):
    capabilities = (
        Capability.NAME
        | Capability.TYPES
        | Capability.CFG
        | Capability.CALLS
        | Capability.DATAFLOW
    )

    def __init__(
        self,
        target: t.Any,
        include_sym: list[str] = [],
        include_nontop: bool = False,
        skip_sym: list[str] = [],
        score_weights: list[float] | None = None,
    ):
        super().__init__(
            include_sym=include_sym,
            include_nontop=include_nontop,
            skip_sym=skip_sym,
            score_weights=score_weights,
        )
        self.target = target

    def __str__(self) -> str:
        return "Ghidra"