"""
config.py

    Defines configuration knobs that can be universally configured by
    any fuzzable client
"""
import typing as t

from os.path import dirname, abspath
from pathlib import Path


def get_project_root() -> Path:
    """Utility for getting root directory of this project"""
    return Path(__file__).parent.parent


# Supported C/C++ source code extensions
# TODO: we should do a very initial parse on the file to determine if it is C++ source
SOURCE_FILE_EXTS: t.List[str] = [".c", ".cpp", ".cc", ".cp" ".cxx", ".h", ".hpp", ".hh"]

# Interesting symbol name patterns to check for fuzzable
INTERESTING_PATTERNS: t.List[str] = [
    # Consuming Inputs
    "parse",
    "read",
    "buf",
    "file",
    "input",
    "str",
    # Decryption Routines
    "encode",
    "decode",
]

# Function name patterns that include INTERESTING_PATTERNS but
# may not be very useful/interesting to us
FALSE_POSITIVE_SIMILARS: t.List[str] = [
    # str
    "destroy"
]

# Data sink call names that should be deemed risky
# TODO: dataset of risky function calls
RISKY_GLIBC_CALL_PATTERNS: t.List[str] = [
    "cmp",
    "cpy",
    "alloc",
    "create",
]
