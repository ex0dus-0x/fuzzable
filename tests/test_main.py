"""
test_main.py

    Tests the libclang-backed source analysis on the bundled C examples, driven
    through a compile_commands.json (the clang backend strictly requires one).
"""

import json
import tempfile
import unittest
from pathlib import Path

from fuzzable.backend.ghidra import ClangAnalysis

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def write_examples_db(directory: Path) -> None:
    """Write a compile_commands.json into `directory` covering the example sources."""
    entries = [
        {
            "directory": str(EXAMPLES),
            "file": str(source),
            "arguments": ["cc", "-std=c11", "-c", str(source)],
        }
        for source in sorted(EXAMPLES.glob("*.c"))
    ]
    (directory / "compile_commands.json").write_text(json.dumps(entries))


class TestClangAnalysis(unittest.TestCase):
    def test_analysis_from_compile_commands_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_examples_db(Path(tmp))
            # accept the compile_commands.json file directly
            analyzer = ClangAnalysis(
                Path(tmp) / "compile_commands.json", include_nontop=True
            )
            results = analyzer.run()

        self.assertGreaterEqual(len(results), 2)
        self.assertEqual(results[0].name, "vulnerable_parse_buf")

    def test_analysis_from_workspace_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_examples_db(Path(tmp))
            # accept a directory containing a compile_commands.json
            analyzer = ClangAnalysis(Path(tmp), include_nontop=True)
            results = analyzer.run()

        self.assertGreaterEqual(len(results), 2)


if __name__ == "__main__":
    unittest.main()
