# fuzzable

Author: __Alan Cao__

_Binary Ninja helper plugin for fuzzable target discovery and experimental harness generation_

## Description

This is a helper Binary Ninja plugin to assist in identifying functions that are optimal targets for fuzzing and dynamic analysis. This is useful for vulnerability researchers wanting to 
fuzz executables or libraries without manual reverse engineering, and need some fast insight about what functions are potential targets to extrapolate for their harnesses.

The plugin also features experimental support for harness generation, which generates a potentially viable AFL/libFuzzer haress from a template based on the target function the user chooses to fuzz.

Check out the blog post detailing the plugin [here](https://codemuch.tech/2021/06/07/fuzzabble/).

## Example

Here is an example of the fuzzable plugin running on [cesanta/mjs](https://github.com/cesanta/mjs),
accuracy identifying targets for fuzzing and further vulnerability assessment:

![Sample](https://github.com/ex0dus-0x/fuzzable/blob/master/screen.png?raw=true "Sample")

## Settings

Given how diverse binaries are, the plugin provides several settings one may choose to tweak for different targets:

* `fuzzable.depth_threshold`

Minimum number of levels in callgraph to be considered optimal for fuzzing.

Functions that automatically have a callgraph depth of >100 will be marked as fuzzable. However, this may be unnecessary in smaller/less
complex binaries, or those that employing inlining.

* `fuzzable.loop_increase_score`

Don't include natural loop as part of the fuzzability score.

The presence of natural loops are incorporated as part of the fuzzability score, since they may denote some form of scanning/parsing
behavior that is worthy to analyze. Turn off if it generates a lot of false positives.

* `fuzzable.skip_stripped`

Ignore including functions that are stripped as part of the final results.

## License

[MIT License](https://codemuch.tech/license.txt)
