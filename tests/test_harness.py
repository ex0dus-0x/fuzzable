"""
test_harness.py

    Tests the snapshot-fuzzing campaign bundle emitter: deriving the SnapshotSpec
    from the ELF fixture and writing a complete, well-formed LibAFL-QEMU bundle.
"""

import ast
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from fuzzable.harnessing.harness import build_spec, emit_bundle
from fuzzable.harnessing.snapshot import resolve_function

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "libbasic.so"


class TestHarnessEmitter(unittest.TestCase):
    def test_build_spec_from_symbol(self):
        spec = build_spec(FIXTURE, symbol="vulnerable_parse_buf")
        self.assertEqual(spec.symbol, "vulnerable_parse_buf")
        self.assertEqual(spec.arch, "x86_64")
        self.assertEqual(
            spec.func_addr, resolve_function(FIXTURE, "vulnerable_parse_buf")
        )
        # x86_64 SysV defaults
        self.assertEqual((spec.data_reg, spec.size_reg), ("rdi", "rsi"))

    def test_build_spec_auto_selects_top_target(self):
        spec = build_spec(FIXTURE)  # no symbol -> top-ranked fuzzable function
        self.assertEqual(spec.symbol, "vulnerable_parse_buf")

    def test_register_overrides(self):
        spec = build_spec(FIXTURE, symbol="free_obj", data_reg="rsi", size_reg="rdx")
        self.assertEqual((spec.data_reg, spec.size_reg), ("rsi", "rdx"))

    def test_emit_bundle_writes_wellformed_files(self):
        spec = build_spec(FIXTURE, symbol="vulnerable_parse_buf")
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "bundle"
            files = emit_bundle(spec, out)

            names = {p.name for p in files}
            self.assertEqual(
                {
                    "snapshot.toml",
                    "fuzzer.py",
                    "build.sh",
                    "run.sh",
                    "README.md",
                    "seed_0",
                    "dict.txt",
                },
                names,
            )

            # config carries the inferred values
            config = (out / "snapshot.toml").read_text()
            self.assertIn('symbol = "vulnerable_parse_buf"', config)
            self.assertIn(f'func_addr = "{spec.func_addr_hex}"', config)
            self.assertIn('data_reg = "rdi"', config)

            # the generated driver is valid Python (no brace-bug / template breakage)
            driver = (out / "fuzzer.py").read_text()
            ast.parse(driver)
            self.assertIn(f"FUNC_ADDR = {spec.func_addr_hex}", driver)

            # scripts are executable
            self.assertTrue((out / "run.sh").stat().st_mode & 0o100)

    def test_unsupported_engine_raises(self):
        spec = build_spec(FIXTURE, symbol="vulnerable_parse_buf")
        with TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                emit_bundle(spec, Path(tmp), engine="afl-bochs")


if __name__ == "__main__":
    unittest.main()
