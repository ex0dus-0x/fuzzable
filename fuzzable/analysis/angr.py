"""
angr.py

    Fallback disassembly backend, most likely for headless analysis.
"""
import typing as t

from angr.analyses.cfg.cfg_fast import CFGFast

from . import AnalysisBackend, AnalysisMode, Fuzzability
from ..metrics import CallScore, CoverageReport


class AngrAnalysis(AnalysisBackend):
    def __str__(self) -> str:
        return "angr"

    def run(self) -> Fuzzability:
        cfg_fast = self.target.analyses.CFGFast()
        analyzed = []
        for _, func in cfg_fast.functions.items():
            name = func.name

            if self.skip_analysis(func):
                continue

            # if recommend mode, filter and run only those that are top-level
            if (
                self.mode == AnalysisMode.RECOMMEND
                and not AngrAnalysis.is_toplevel_call(func)
            ):
                continue

            score = self.analyze_call(name, func)
            analyzed += [score]

        return super()._rank_fuzzability(analyzed)

    def analyze_call(self, name: str, func: t.Any) -> CallScore:
        stripped = "sub_" in name

        # no need to check if no name available
        # TODO: maybe we should run this if a signature was recovered
        fuzz_friendly = False
        if not stripped:
            fuzz_friendly = AngrAnalysis.is_fuzz_friendly(name)

        return CallScore(
            name=name,
            toplevel=AngrAnalysis.is_toplevel_call(func),
            fuzz_friendly=fuzz_friendly,
            risky_sinks=self.risky_sinks(func),
            contains_loop=AngrAnalysis.contains_loop(func),
            coverage_depth=self.get_coverage_depth(func),
            stripped=stripped,
        )

    def skip_analysis(self, func: t.Any) -> bool:
        name = func.name

        # ignore imported functions from other libraries, ie glibc or win32api
        if func.is_plt or func.is_syscall:
            return True

        if name.startswith("_"):
            return True

        # if set, ignore all stripped functions for faster analysis
        if ("sub_" in name) or ("Unresolvable" in name):
            return True

        return False

    def is_toplevel_call(self, target: t.Any) -> bool:
        pass

    def risky_sinks(self, func: t.Any) -> int:
        pass

    def get_coverage_depth(self, func: t.Any) -> int:
        pass

    def contains_loop(self, func: t.Any) -> bool:
        pass

    def get_cyclomatic_complexity(self) -> int:
        """
        HEURISTIC

        M = E − N + 2P
        """
        pass
