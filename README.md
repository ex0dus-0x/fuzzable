# fuzzable

Framework for Automating _Fuzzable_ Target Discovery with Static Analysis

## Introduction

Vulnerability researchers conducting security assessments on software will often harness the capabilities of coverage-guided fuzzing through powerful tools like AFL++ and libFuzzer. This is important as it automates the bughunting process and reveals exploitable conditions in targets quickly. However, when encountering large and complex codebases or closed-source binaries, researchers have to painstakingly dedicate time to manually audit and reverse engineer them to identify functions where fuzzing-based exploration can be useful.

__Fuzzable__ is a framework that integrates both with C/C++ source code and binaries to assist vulnerability researchers in identifying function targets that are viable for fuzzing. This is done by applying several static analysis-based heuristics to pinpoint risky behaviors in the software and the functions that executes them. Researchers can then utilize the framework to generate basic harness templates, which can then be used to hunt for vulnerabilities, or to be integrated as part of a continuous fuzzing pipeline, such as Google's oss-fuzz.

In addition to running as a standalone tool, Fuzzable is also integrated as a plugin for Binary Ninja, with support for other disassembly backends being developed.

Check out the blog post detailing the plugin [here](https://codemuch.tech/2021/06/07/fuzzabble/).

## Features

## Usage

Some binary targets may require some sanitizing (ie. signature matching, or identifying functions from inlining), and therefore 
__fuzzable__ primarily uses Binary Ninja as a disassembly backend because of it's ability to effectively solve these problems.
Therefore, it can be utilized both as a standalone tool and plugin.

Since Binary Ninja isn't accessible to all and there may be a demand to utilize this in the cloud at scale, a [falcon](https://github.com/falconre/falcon)
_fallback_ backend is also supported. I anticipate to incorporate other disassemblers down the road as well.

### Command Line (Standalone)

If you have Binary Ninja Commercial, be sure

```
$ python3 /Applications/Binary\ Ninja.app/Contents/Resources/scripts/install_api.py
```

Now install `fuzzable` with `pip`:

```
$ pip install fuzzable
```

### Binary Ninja Plugin

Here is an example of the __fuzzable__ plugin running on [cesanta/mjs](https://github.com/cesanta/mjs),
accuracy identifying targets for fuzzing and further vulnerability assessment:

![Sample](https://github.com/ex0dus-0x/fuzzable/blob/main/screen.png?raw=true "Sample")

## Settings

Given how diverse binaries are, the plugin provides several settings one may choose to tweak for different targets:

* `depth_threshold`

Minimum number of levels in callgraph to be considered optimal for fuzzing.

Functions that automatically have a callgraph depth of >100 will be marked as fuzzable. However, this may be unnecessary in smaller/less
complex binaries, or those that employing inlining.

* `loop_increase_score`

Don't include natural loop as part of the fuzzability score.

The presence of natural loops are incorporated as part of the fuzzability score, since they may denote some form of scanning/parsing
behavior that is worthy to analyze. Turn off if it generates a lot of false positives.

* `skip_stripped`

Ignore including functions that are stripped as part of the final results.

## License

[MIT License](https://codemuch.tech/license.txt)
