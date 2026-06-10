"""
test_snapshot.py

    Tests the binary-only snapshot fuzzer against the committed ELF fixture
    (an x86_64 shared object built from examples/libbasic.c). vulnerable_parse_buf
    memcpy's an attacker-controlled length into a fixed-size buffer, so a large
    input must surface as a memory-safety violation under emulation.
"""

import unittest
from pathlib import Path

from fuzzable.harnessing.snapshot import Crash, SnapshotFuzzer

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "libbasic.so"


class TestSnapshotFuzzer(unittest.TestCase):
    def setUp(self):
        self.fuzzer = SnapshotFuzzer(FIXTURE, "vulnerable_parse_buf")

    def test_benign_input_does_not_crash(self):
        self.assertIsNone(self.fuzzer.run_once(b"hello world"))

    def test_oversized_input_crashes(self):
        crash = self.fuzzer.run_once(b"A" * 4000)
        self.assertIsInstance(crash, Crash)
        self.assertNotEqual(crash.exception, 0)

    def test_fuzz_discovers_the_overflow(self):
        crashes = self.fuzzer.fuzz(iterations=300)
        self.assertGreaterEqual(len(crashes), 1)

    def test_missing_symbol_raises(self):
        with self.assertRaises(ValueError):
            SnapshotFuzzer(FIXTURE, "no_such_function")


if __name__ == "__main__":
    unittest.main()
