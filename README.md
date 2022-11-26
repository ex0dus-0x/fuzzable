# Fuzzable

[![Build Status](https://github.com/ex0dus-0x/fuzzable/actions/workflows/main.yml/badge.svg)](https://github.com/ex0dus-0x/fuzzable/actions)
[![PyPI version](https://badge.fury.io/py/fuzzable.svg)](https://badge.fury.io/py/fuzzable)
[![Blackhat](https://raw.githubusercontent.com/toolswatch/badges/master/arsenal/usa/2022.svg)](https://raw.githubusercontent.com/toolswatch/badges/master/arsenal/usa/2022.svg)

Framework for Automating _Fuzzable_ Target Discovery with Static Analysis

![example](https://raw.githubusercontent.com/ex0dus-0x/fuzzable/main/extras/cli.png "CLI Example")

## Introduction

Vulnerability researchers conducting security assessments on software will often harness the capabilities of coverage-guided fuzzing through powerful tools like AFL++ and libFuzzer. This is important as it automates the bughunting process and reveals exploitable conditions in targets quickly. However, when encountering large and complex codebases or closed-source binaries, researchers have to painstakingly dedicate time to manually audit and reverse engineer them to identify functions where fuzzing-based exploration can be useful.

__Fuzzable__ is a framework that integrates both with C/C++ source code and binaries to assist vulnerability researchers in identifying function targets that are viable for fuzzing. This is done by applying several static analysis-based heuristics to pinpoint risky behaviors in the software and the functions that executes them. Researchers can then utilize the framework to generate basic harness templates, which can then be used to hunt for vulnerabilities, or to be integrated as part of a continuous fuzzing pipeline, such as Google's [oss-fuzz](https://github.com/google/oss-fuzz) project.

In addition to running as a standalone tool, Fuzzable is also integrated as a plugin for the [Binary Ninja ](https://binary.ninja) disassembler, with support for other disassembly backends being developed.

Check out the original blog post detailing the tool [here](https://codemuch.tech/2021/06/07/fuzzabble/), which highlights the technical specifications of the static analysis heuristics and how this tool came about. This tool is also featured at [Black Hat Arsenal USA 2022](https://www.blackhat.com/us-22/arsenal/schedule/index.html#automating-fuzzable-target-discovery-with-static-analysis-26726).

## Features

* Supports analyzing __binaries__ (with [Angr](https://angr.io) and [Binary Ninja](https://binary.ninja)) and
__source code__ artifacts (with [tree-sitter](https://tree-sitter.github.io/tree-sitter/)).
* Run static analysis both as a __standalone CLI tool__ or a __Binary Ninja plugin__.
* __Harness generation__ to ramp up on creating fuzzing campaigns quickly.

## Installation

Some binary targets may require some sanitizing (ie. signature matching, or identifying functions from inlining), and therefore 
__fuzzable__ primarily uses Binary Ninja as a disassembly backend because of it's ability to effectively solve these problems. Therefore, it can be utilized both as a standalone tool and plugin.

Since Binary Ninja isn't accessible to all and there may be a demand to utilize for security assessments and potentially scaling up in the cloud, an [angr](https://github.com/angr/angr)
_fallback_ backend is also supported. I anticipate to incorporate other disassemblers down the road as well (priority: Ghidra).

### Command Line (Standalone)

If you have Binary Ninja Commercial, be sure to install the API for standalone headless usage:

```
$ python3 /Applications/Binary\ Ninja.app/Contents/Resources/scripts/install_api.py
```

Install with `pip`:

```
$ pip install fuzzable
```

### Manual/Development Build

We use [poetry](https://python-poetry.org) for dependency management and building. To do a manual build, clone the repository with the third-party modules:

```
$ git clone --recursive https://github.com/ex0dus-0x/fuzzable
```

To install manually:

```
$ cd fuzzable/

# without poetry
$ pip install .

# with poetry
$ poetry install

# with poetry for a development virtualenv
$ poetry shell
```

You can now analyze binaries and/or source code with the tool!

```
# analyzing a single shared object library binary
$ fuzzable analyze examples/binaries/libbasic.so

# analyzing a single C source file
$ fuzzable analyze examples/source/libbasic.c

# analyzing a workspace with multiple C/C++ files and headers
$ fuzzable analyze examples/source/source_bundle/
```

### Binary Ninja Plugin

__fuzzable__ can be easily installed through the Binary Ninja plugin marketplace by going to `Binary Ninja > Manage Plugins` and searching for it. Here is an example of the __fuzzable__ plugin running,
accuracy identifying targets for fuzzing and further vulnerability assessment:

![binja_example](/extras/binja.png "Binary Ninja Example")

## Usage

__fuzzable__ comes with various options to help better tune your analysis. More will be supported in future plans and any feature requests made. 

### Static Analysis Heuristics

To determine fuzzability, __fuzzable__ utilize several heuristics to determine which targets are the most viable to target for dynamic analysis. These heuristics are all weighted differently using the [scikit-criteria](https://scikit-criteria.quatrope.org/en/latest/tutorial/quickstart.html) library, which utilizes _multi-criteria decision analysis_ to determine the best candidates. These metrics and are there weights can be seen here:

| Heuristic             | Description                                                 | Weight |
|-----------------------|-------------------------------------------------------------|--------|
| Fuzz Friendly Name    | Symbol name implies behavior that ingests file/buffer input | 0.3    |
| Risky Sinks           | Arguments that flow into risky calls (ie memcpy)            | 0.3    |
| Natural Loops         | Number of loops detected with the dominance frontier        | 0.05   |
| Cyclomatic Complexity | Complexity of function target based on edges + nodes        | 0.05   |
| Coverage Depth        | Number of callees the target traverses into                 | 0.3    |

> As mentioned, check out the [technical blog post](https://codemuch.tech/2021/06/07/fuzzabble/) for a more in-depth look into why and how these metrics are utilized.

Many metrics were largely inspired by [Vincenzo Iozzo's original work in 0-knowledge fuzzing](https://resources.sei.cmu.edu/asset_files/WhitePaper/2010_019_001_53555.pdf).

Every targets you want to analyze is diverse, and __fuzzable__ will not be able to account for every edge case behavior in the program target. Thus, it may be important during analysis to _tune_ these weights appropriately to see if different results make more sense for your use case. To tune these weights in the CLI, simply specify the `--score-weights` argument:

```
$ fuzzable analyze <TARGET> --score-weights=0.2,0.2,0.2,0.2,0.2
```

### Analysis Filtering

By default, __fuzzable__ will filter out function targets based on the following criteria:

* __Top-level entry calls__ - functions that aren't called by any other calls in the target. These are ideal entry points that have potentially very high coverage.
* __Static calls__ - _(source only)_ functions that are `static` and aren't exposed through headers.
* __Imports__ - _(binary only)_ other library dependencies being used by the target's implementations.

To see calls that got filtered out by __fuzzable__, set the `--list_ignored` flag:

```
$ fuzzable analyze --list-ignored <TARGET>
```

In Binary Ninja, you can turn this setting in `Settings > Fuzzable > List Ignored Calls`.

In the case that __fuzzable__ falsely filters out important calls that should be analyzed, it is recommended to use `--include-*` arguments
to include them during the run:

```
# include ALL non top-level calls that were filtered out
$ fuzzable analyze --include-nontop <TARGET>

# include specific symbols that were filtered out
$ fuzzable analyze --include-sym <SYM> <TARGET>
```

In Binary Ninja, this is supported through `Settings > Fuzzable > Include non-top level calls` and `Symbols to Exclude`.

### Harness Generation

Now that you have found your ideal candidates to fuzz, __fuzzable__ will also help you generate fuzzing harnesses that are (almost) ready to instrument and compile for use with either a file-based fuzzer (ie. AFL++, Honggfuzz) or in-memory fuzzer (libFuzzer). To do so in the CLI:

```
# generate harness from a candidate
$ fuzzable create-harness target --symbol-name=some_unsafe_call

# make minimal and necessary modifications to the harness
$ vim target_some_unsafe_call_harness.cpp

# example compilation for AFL-QEMU, which is specified in the comments of the generated harness
$ clang target_some_unsafe_call_harness.cpp -no-pie -o target_some_unsafe_call_harness -ldl

# create your base seeds, ideally should be more well-formed for input
$ mkdir in/
$ echo "seed" >> in/seed

# start black box fuzzing
$ afl-fuzz -Q -m none -i in/ -o out/ -- ./target_some_unsafe_call_harness
```

If this target is a source codebase, the [generic source template](/templates/linux_source_harness.cpp) will be used. 

If the target is a binary, the [generic black-box template](/templates/linux_closed_source_harness.cpp) will be used, which ideally can be used with a fuzzing emulation mode like [AFL-QEMU](https://github.com/mirrorer/afl/blob/master/qemu_mode/README.qemu). A copy of the binary will also be created as a shared object if the symbol isn't exported directly to be `dlopen`ed using [LIEF](https://lief-project.github.io).

At the moment, this feature is quite rudimentary, as it simply will create a standalone C++ harness populated with the appropriate parameters, and will not auto-generate code that is needed for any runtime behaviors (ie. instantiating and freeing structures). However, the templates created for __fuzzable__ should get still get you running quickly. Here are some ambitious features I would like to implement down the road:

* Full harness synthesis - harnesses will work directly with absolutely no manual changes needed.
* Synthesis from potential unit tests using the [DeepState](https://github.com/trailofbits/deepstate) framework _(Source only)_.
* Immediate deployment to a managed continuous fuzzing fleet.

### Exporting Reports

__fuzzable__ supports generating reports in various formats. The current ones that are supported are JSON, CSV and Markdown. This can be useful if you are utilizing this as part of automation where you would like to
ingest the output in a serializable format.

In the CLI, simply pass the `--export` argument with a filename with the appropriate extension:

```
$ fuzzable analyze --export=report.json <TARGET>
```

In Binary Ninja, go to `Plugins > Fuzzable > Export Fuzzability Report > ...` and select the format you want to
export to and the path you want to write it to.

## Contributing

This tool will be continuously developed, and any help from external mantainers are appreciated!

* Create an [issue](https://github.com/ex0dus-0x/fuzzable/issues) for feature requests or bugs that you have come across.
* Submit a [pull request](https://github.com/ex0dus-0x/fuzzable/pulls) for fixes and enhancements that you would like to see contributed to this tool.

## License

Fuzzable is licensed under the [MIT License](https://codemuch.tech/license.txt).
