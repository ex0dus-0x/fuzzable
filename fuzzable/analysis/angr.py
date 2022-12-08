"""
angr.py

    Fallback disassembly backend with angr, most likely for headless analysis.
"""
import typing as t

import angr
from angr.analyses.reaching_definitions.dep_graph import DepGraph
from angr.knowledge_plugins.functions.function import Function
from angr.procedures.definitions.glibc import _libc_decls

from pathlib import Path

from . import AnalysisBackend, AnalysisException, Fuzzability, DEFAULT_SCORE_WEIGHTS
from ..metrics import CallScore
from ..log import log


class AngrAnalysis(AnalysisBackend):
    def __init__(
        self,
        target: Path,
        include_sym: t.List[str] = [],
        include_nontop: bool = False,
        skip_sym: t.List[str] = [],
        skip_stripped: bool = False,
        score_weights: t.List[float] = DEFAULT_SCORE_WEIGHTS,
    ):
        project = angr.Project(target, load_options={"auto_load_libs": False})
        super().__init__(
            project, include_sym, include_nontop, skip_sym, skip_stripped, score_weights
        )

        log.debug("Doing initial CFG analysis on target")
        self.cfg = self.target.analyses.CFG(
            resolve_indirect_jumps=True,
            cross_references=True,
            force_complete_scan=False,
            normalize=True,
            symbols=True,
        )

    def __str__(self) -> str:
        return "angr"

    def run(self) -> Fuzzability:
        log.debug("Iterating over functions")
        for func in self.cfg.functions.values():
            name = func.name
            addr = str(hex(func.addr))

            # just in case repeats show up again
            if name in self.visited:
                continue
            self.visited += [name]

            log.debug(f"Checking if we should ignore {name}")
            if self.skip_analysis(func):
                log.warning(f"Skipping {name} from fuzzability analysis.")
                self.skipped[name] = addr
                continue

            log.debug(f"Checking if {name} is a top-level call")
            if not self.include_nontop and not self.is_toplevel_call(func):
                log.warning(
                    f"Skipping {name} (not top-level) from fuzzability analysis."
                )
                self.skipped[name] = addr
                continue

            log.info(f"Starting analysis for function {name}")
            score = self.analyze_call(name, func)
            self.scores += [score]

        if len(self.scores) == 0:
            raise AnalysisException(
                "No suitable function symbols filtered for analysis."
            )

        return super()._rank_fuzzability(self.scores)

    def analyze_call(self, name: str, func: Function) -> CallScore:
        stripped = "sub_" in name
        addr = str(hex(func.addr))

        # no need to check if no name available
        # TODO: maybe we should run this if a signature was recovered
        fuzz_friendly = 0
        if not stripped:
            log.debug(f"{name} - checking if fuzz friendly")
            fuzz_friendly = AngrAnalysis.is_fuzz_friendly(name)

        return CallScore(
            name=name,
            loc=addr,
            toplevel=self.is_toplevel_call(func),
            fuzz_friendly=fuzz_friendly,
            risky_sinks=self.risky_sinks(func),
            natural_loops=self.natural_loops(func),
            coverage_depth=self.get_coverage_depth(func),
            cyclomatic_complexity=self.get_cyclomatic_complexity(func),
            stripped=stripped,
        )

    def skip_analysis(self, func: Function) -> bool:
        name = func.name

        if super().skip_analysis(name):
            return True

        # ignore imported functions or syscalls
        if func.is_syscall:
            return True

        # ignore common glibc calls
        if name in _libc_decls:
            return True

        # if set, ignore all stripped functions for faster analysis
        if "Unresolvable" in name:
            return True

        return False

    def is_toplevel_call(self, target: Function) -> bool:
        return (
            len(set(target._function_manager.callgraph.predecessors(target.addr))) == 0
        )

    def risky_sinks(self, func: Function) -> int:
        log.debug(f"{func.name} - checking for risky sinks")

        """
        # TODO: do an interprocedural analysis starting from the function
        func_cfg = self.target.analyses.CFGFast(
            start_at_entry=False,
            function_starts=[func.addr]
        )
        """

        risky_sinks = 0
        for cs in func.get_call_sites():
            insn = func.get_call_target(cs)
            call_site = self.cfg.kb.functions.function(addr=insn)

            # TODO: should we traverse further if not a imported func
            if AngrAnalysis._is_risky_call(call_site.name):
                risky_sinks += 1

            """
            rd = self.target.analyses.ReachingDefinitions(
                subject=func,
                func_graph=func.graph,
                cc=func.calling_convention,
                observation_points=[
                    (
                        "insn",
                        insn,
                        0,
                    )
                ],
                dep_graph=DepGraph(),
            )
            """

        return risky_sinks

    def get_coverage_depth(self, target: Function) -> int:
        """
        Calculates coverage depth by doing a depth first search on function call graph,
        and return a final depth and flag denoting recursive implementation.
        """
        log.debug(f"{target.name} - getting coverage depth")
        depth = 0

        # as we iterate over callees, add to a callstack and iterate over callees
        # for those as well, adding to the callgraph until we're done with all
        callstack = [target]
        while callstack:

            # increase depth as we finish iterating over callees for another func
            func = callstack.pop()
            depth += 1

            # add all childs to callgraph, and add those we haven't recursed into callstack
            for call in func.functions_called():
                if call.name not in self.visited:
                    callstack += [call]

                self.visited += [call.name]

        return depth

    def natural_loops(self, func: Function) -> int:
        log.debug(f"{func.name} - getting number of natural loops")
        dominance_frontier = self.target.analyses.DominanceFrontier(func)
        if dominance_frontier.frontiers:
            return len(dominance_frontier.frontiers)

        return 0

    def get_cyclomatic_complexity(self, func: Function) -> int:
        log.debug(f"{func.name} - calculating cyclomatic complexity")
        num_blocks = 0
        for _ in func.blocks:
            num_blocks += 1

        # do a CFG analysis starting at the func address
        cfg = self.target.analyses.CFGFast(
            force_complete_scan=False, start_at_entry=hex(func.addr)
        )
        num_edges = len(cfg.graph.edges())
        return num_edges - num_blocks + 2
