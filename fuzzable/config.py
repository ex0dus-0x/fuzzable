"""
config.py

    Defines configuration knobs that can be universally configured by
    any fuzzable client
"""
import typing as t

# Supported source code paths
SOURCE_FILE_EXTS = [".c", ".cpp", ".cc", ".h", ".hpp"]

# Interesting symbol name patterns to check for fuzzable
INTERESTING_PATTERNS: t.List[str] = [
    "Parse",
    "Read",
    "Buf",
    "File",
    "Input",
    "String",
    "Decode",
]

# TODO: dataset of risky function calls
RISKY_GLIBC_CALL_PATTERNS: t.List[str] = [
    "cmp",
    "cpy",
    "free",
]

SETTINGS = {}
