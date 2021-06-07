# fuzzable

Author: __Alan Cao__

_Binary Ninja helper plugin for fuzzable target discovery and experimental harness generation_

## Description

This is a helper Binary Ninja plugin to assist in identifying functions that are optimal targets for fuzzing and dynamic analysis. This is useful for vulnerability researchers wanting to 
fuzz executables or libraries without manual reverse engineering, and need some fast insight about what functions are potential targets to extrapolate for their harnesses.

The plugin also features experimental support for harness generation, which generates a potentially viable AFL/libFuzzer haress from a template based on the target function the user chooses to fuzz.

## Example

Here is an example of the fuzzable plugin running on Binary Ninja's `libbinaryninjacore.so` dependency,
accuracy identifying targets that are optimal for fuzzing and further vulnerability assessment:

![Sample](https://github.com/ex0dus-0x/fuzzable/blob/master/screen.png?raw=true "Sample")

## License

[MIT](https://codemuch.tech/license.txt)
