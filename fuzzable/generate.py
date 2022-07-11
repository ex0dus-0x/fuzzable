"""
generate.py

    Creates template harnesses for a given target.
"""
import typing as t

import lief
from lief import ELF

from pathlib import Path


def transform_elf_to_so(
    elf_path: Path, exports: t.List[str], override_path: t.Optional[str] = None
) -> None:
    """
    Uses LIEF to check if an ELF executable can be transformed into a shared object with exported
    symbols for fuzzing.
    """
    lib = lief.parse(elf_path)

    # check if shared object or PIE binary
    # TODO: stronger checks for shared object
    if lib.header.file_type is not ELF.E_TYPE.DYNAMIC and not ".so" in elf_path.suffix:
        return None

    for sym in exports:
        addr = lief.get_function_address(sym)
        lib.add_exported_function(addr, sym)

    if not override_path:
        lib.write(elf_path + "_exported.so")
    else:
        lib.write(override_path)
