# fuzzable

Binary Ninja helper plugin for fuzzable target discovery

## Introduction

This is a helper Binary Ninja plugin to assist in identifying functions that are optimal targets for fuzzing and dynamic analysis.
This is useful for vulnerability researchers wanting to fuzz black-box executables or libraries, and need some fast insight about what functions are potential targets to extrapolate
for their harnesses.

TODO: rudimentary target generation

## Methodology

Each function is vetted and parsed from the binary view, and a _fuzzability score_ is assigned based on the following set of metrics applied during
analysis:

* __Function Signature__:
    * Stripped?
    * Interesting function name?
    * Directly consumable parameters?

* __Static Analysis__:
    * High coverage depth?
    * High recursive/cyclomatic complexity?
