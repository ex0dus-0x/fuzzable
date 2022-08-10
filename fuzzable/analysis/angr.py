"""
angr.py

    Fallback disassembly backend, most likely for headless analysis.
"""
import typing as t

import angr
from angr.analyses.reaching_definitions.dep_graph import DepGraph
from angr.knowledge_plugins.key_definitions.atoms import Atom
from angr.knowledge_plugins.functions.function import Function
from angr.procedures.definitions.glibc import _libc_decls

from pathlib import Path

from . import AnalysisBackend, AnalysisMode, Fuzzability, DEFAULT_SCORE_WEIGHTS
from ..metrics import CallScore
from ..log import log

# TODO: inherit angr.Analysis
class AngrAnalysis(AnalysisBackend):
    def __init__(
        self,
        target: Path,
        mode: AnalysisMode,
        score_weights: t.List[float] = DEFAULT_SCORE_WEIGHTS,
        skip_stripped: bool = False,
    ):
        project = angr.Project(target, load_options={"auto_load_libs": False})
        super().__init__(project, mode, score_weights)

        log.debug("Doing initial CFG analysis on target")
        self.cfg = self.target.analyses.CFGFast()
        _ = self.target.analyses.CompleteCallingConventions(recover_variables=True)

    def __str__(self) -> str:
        return "angr"

    def run(self) -> Fuzzability:
        log.debug("Iterating over functions")
        for _, func in self.cfg.functions.items():
            name = func.name

            if name in self.visited:
                continue
            self.visited += [name]

            if self.mode == AnalysisMode.RECOMMEND and self.skip_analysis(func):
                log.warning(f"Skipping {name} from fuzzability analysis.")
                self.skipped[name] = str(hex(func.addr))
                continue

            # if recommend mode, filter and run only those that are top-level
            if self.mode == AnalysisMode.RECOMMEND and not self.is_toplevel_call(func):
                self.skipped[name] = str(hex(func.addr))
                continue

            log.info(f"Conducting fuzzability analysis on function symbol '{name}'")
            score = self.analyze_call(name, func)
            self.scores += [score]

        return super()._rank_fuzzability(self.scores)

    def analyze_call(self, name: str, func: Function) -> CallScore:
        stripped = "sub_" in name

        # no need to check if no name available
        # TODO: maybe we should run this if a signature was recovered
        fuzz_friendly = 0
        if not stripped:
            log.debug(f"{name} - checking if fuzz friendly")
            fuzz_friendly = AngrAnalysis.is_fuzz_friendly(name)

        return CallScore(
            name=name,
            loc=str(hex(func.addr)),
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

        # ignore imported functions or syscalls
        if func.is_syscall:
            return True

        # ignore common glibc calls
        if name in _libc_decls:
            return True

        # ignore instrumentation
        # if name.startswith("__"):
        #    return True

        # ignore runtime calls from the binary
        if name in ["_init", "frame_dummy", "call_weak_fn", "$x", "_fini"]:
            return True

        # if set, ignore all stripped functions for faster analysis
        if "Unresolvable" in name:
            return True

        return False

    def is_toplevel_call(self, target: Function) -> bool:
        """
        TODO: make this work with less of a performance downgrade.
        """
        cfg_nodes = self.cfg.get_all_nodes(target.addr)
        if len(cfg_nodes) == 0:
            return True
        # return self.cfg.get_predecessors(cfg_nodes[0]) == 0
        return True

    def risky_sinks(self, func: Function) -> int:
        """
        TODO: really slow
        """
        log.debug(f"{func.name} - checking for risky sinks")

        target = self.target.kb.functions.function(name=func.name)
        program_rda = self.target.analyses.ReachingDefinitions(
            subject=target, dep_graph=DepGraph()
        )

        """
        for sink_name in ["memcpy", "strcpy", ""]:
            sink_function = self.target.kb.functions.function(name=sink_name)

            parameter_position = 1
            parameter_type = _libc_decls[sink_name].args[parameter_position]
            parameter_atom = Atom.from_argument(
                sink_function.calling_convention.arg_locs()[parameter_position],
                self.target.arch.registers
            )
        """

        return len(func.get_call_sites())

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
