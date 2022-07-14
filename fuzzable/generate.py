"""
generate.py

    Creates template harnesses for a given target.
"""
import typing as t

import lief
from lief import ELF

from pathlib import Path


def transform_elf_to_so(
    path: Path, lib: lief.Binary, exports: t.List[str], override_path: t.Optional[str]
) -> t.Optional[str]:
    """
    Uses LIEF to check if an ELF executable can be transformed into a shared object with exported
    symbols for fuzzing.
    """

    # check if shared object or PIE binary
    # TODO: stronger checks for shared object
    if lib.header.file_type is not ELF.E_TYPE.DYNAMIC and not ".so" in path.suffix:
        return None

    for sym in exports:
        addr = lief.get_function_address(sym)
        lib.add_exported_function(addr, sym)

    if not override_path:
        lib.write(path + "_exported.so")
    else:
        lib.write(override_path)

    return path + "_exported.so"


def generate_harness(
    target: Path, output: t.Optional[Path], file_fuzzing: bool, libfuzzer: bool
) -> None:
    """ """
    template_type = None

    with open(Path("templates" / "linux_closed_source_harness.cpp"), "r") as fd:
        template = fd.read()

    template = template.replace("{NAME}", target)
    template = template.replace("{binary}", target)
    template = template.replace("{type_arg}", target)

    # set a FILE_FUZZING
    if file_fuzzing:
        pass
    if libfuzzer:
        pass

    if output is None:
        output = target + "_harness.cc"

    with open(output) as fd:
        fd.write(template)
