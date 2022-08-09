"""
generate.py

    Creates template harnesses for a given target.
"""
import os
import typing as t

import lief
from lief import ELF

from pathlib import Path

from .log import log
from .config import get_project_root


def generate_harness(
    target_path: str,
    function_name: str,
    return_type: t.Optional[str] = None,
    params: t.Optional[t.List[str]] = None,
    harness_path: t.Optional[str] = None,
    output: t.Optional[str] = None,
) -> None:
    """
    Populate a harness template with given parameters and generate harness to path.
    """

    abspath = os.path.basename(target_path)
    name = abspath.split(".")[0]

    # override template if set
    template_path = get_project_root() / "templates" / "linux_closed_source_harness.cpp"
    if harness_path:
        template_path = harness_path

    log.debug("Reading harness template")
    with open(template_path, "r", encoding="utf-8") as template_file:
        template = template_file.read()

    log.debug("Replacing parameters in template")
    template = template.replace("{NAME}", name)
    template = template.replace("{path}", abspath)
    template = template.replace("{function_name}", function_name)

    # these are optional and can be populated by the user
    if return_type:
        template = template.replace("{return_type}", return_type)
    if params:
        if len(params) != 0:
            template = template.replace("{type_args}", ",".join(params))

    # override harness output if set
    harness = f"{name}_{function_name}_harness.cpp"
    if output is not None:
        harness = output

    log.debug(f"Writing harness to path {harness}")
    with open(harness, "w", encoding="utf-8") as template_file:
        template_file.write(template)


def transform_elf_to_so(
    path: Path,
    lib: lief.Binary,
    export: t.Union[str, int],
    override_path: t.Optional[Path],
) -> t.Optional[Path]:
    """
    Helper that uses LIEF to check if an ELF executable can be transformed into a shared object
    with exported symbols for fuzzing.
    """

    # check if shared object or PIE binary
    # TODO: stronger checks for shared object
    log.info(f"Checking if {path} needs to be transformed into a shared object")
    if lib.header.file_type is not ELF.E_TYPE.DYNAMIC and ".so" in path.suffix:
        log.info("No need to transform binary into a shared object")
        return path

    log.info(f"Attempting to export the symbol in binary {export}")

    # if hex addr specified, export address directly and set name
    if isinstance(export, int):
        lib.add_exported_function(export, f"sub_{export}")

    # otherwise find the address of the symbol name and export it
    else:
        addr = lib.get_function_address(export)
        lib.add_exported_function(addr, export)

    # override the generated shared object to write to if set
    path = path.name.split(".")[0] + ".so"
    if override_path:
        path = str(override_path)

    log.info(
        f"Writing the ELF binary into a shared object for harness genaration at {path}"
    )
    lib.write(path)
    return Path(path)
