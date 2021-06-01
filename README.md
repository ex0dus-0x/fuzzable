# fuzzable

__Author__: Alan Cao <ex0dus-0x>

_Binary Ninja helper plugin for fuzzable target discovery and experimental harness generation_

## Description

This is a helper Binary Ninja plugin to assist in identifying functions that are optimal targets for fuzzing and dynamic analysis. This is useful for vulnerability researchers wanting to 
fuzz black-box executables or libraries, and need some fast insight about what functions are potential targets to extrapolate for their harnesses.

The plugin also features experimental support for harness generation, which generates a potentially viable AFL/libFuzzer haress from a template based on the target function the user chooses to fuzz.

## Example

TODO

## License

[MIT](https://codemuch.tech/license.txt)
