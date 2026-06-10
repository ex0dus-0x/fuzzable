# Fuzzable

[![Build Status](https://github.com/ex0dus-0x/fuzzable/actions/workflows/main.yml/badge.svg)](https://github.com/ex0dus-0x/fuzzable/actions)
[![PyPI version](https://badge.fury.io/py/fuzzable.svg)](https://badge.fury.io/py/fuzzable)

Fuzz Target Discovery and Harness Generation Tool

## Introduction

__Fuzzable__ is a tool and disassembler plugin that does best-effort fuzz target discovery and harness synthesis for binaries and C/C++ source code. This is done by computing static analysis metrics for target functions, and ranking them through [multi-criteria decision making (MCDA)](https://www.researchgate.net/publication/374540287_A_comprehensive_guide_to_the_TOPSIS_method_for_multi-criteria_decision_making). Identified targets can then be harnessed into an outputted fuzzing workspace.

This tool conducts binary analysis with [miasm](https://miasm.re/blog/) and [Binary Ninja](http://binary.ninja/) as backends.

Check out the [original blog post](https://codemuch.tech/2021/06/07/fuzzabble/). This tool is also featured at [Black Hat Arsenal USA 2022](https://www.blackhat.com/us-22/arsenal/schedule/index.html#automating-fuzzable-target-discovery-with-static-analysis-26726).

## Features

## Installation

### Command Line (Standalone)

```bash
pipx install fuzzable
```

### Manual Build

TODO

```bash
```

## Usage

Get started by running on either a target binary or a source workspace's `compile_commands.json`, for example on the included test target:

```bash
# run directly against the binary
fuzzable rank <TARGET>

# this lets clangd build an index. also output as json
fuzzable rank <TARGET> --json
```

### Filtering

By default, __fuzzable__ will not operate on imports, static methods, and prominently, functions that don't have any other callers in the target (top-level calls).

To see calls that got filtered out by __fuzzable__, set the `--list_ignored` flag:

```bash
fuzzable rank --list-ignored <TARGET>
```

If calls are falsely being figured, use the `--include-*` flags:

```bash
# include ALL non top-level calls that were filtered out
fuzzable rank --include-nontop <TARGET>

# include specific symbols that were filtered out
fuzzable rank --include-sym <SYM> <TARGET>
```

### In-process Fuzzing (binary-only)

__fuzzable__ can attempt dumb in-process fuzzing against a specified target

### Harness Generation (binary-only)

From a more efficient campaign, a workspace containing a generated harness and runner artifacts can be generated for use with libAFL + QEMU/QASAN.

## Notes

### Ranking

To determine fuzzability, __fuzzable__ measures several per-function heuristics and combines them with _multi-criteria decision analysis_. Each metric is `log1p`-transformed, then ranked with __TOPSIS__ (closeness to the ideal vs. anti-ideal target). By default the metric weights are derived __objectively from the data__ via Shannon-entropy weighting — features that discriminate strongly among the analyzed functions get more weight, and non-informative (near-constant) features are automatically ignored — so there are no hand-tuned weights to misconfigure. The metrics are:

| Heuristic             | Description                                                 |
|-----------------------|-------------------------------------------------------------|
| Fuzz Friendly Name    | Symbol name implies behavior that ingests file/buffer input |
| Risky Sinks           | Arguments that flow into risky calls (ie memcpy)            |
| Natural Loops         | Number of loops detected in the function                    |
| Cyclomatic Complexity | Complexity of function target based on edges + nodes        |
| Coverage Depth        | Number of callees the target traverses into                 |

Each result also carries a per-metric __contribution__ breakdown.

## License

Fuzzable is licensed under the [MIT License](https://codemuch.tech/license.txt).
