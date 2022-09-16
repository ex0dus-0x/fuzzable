"""
test_generate.py
"""
import unittest
from pathlib import Path

# from fuzzable import generate


class TestHarnessGen(unittest.TestCase):
    def test_basic(self):
        data = [1, 2, 3]
        result = sum(data)
        self.assertEqual(result, 6)

    # def test_transform_elf_to_so(self):
    #    generate.transform_elf_to_so()


if __name__ == "__main__":
    unittest.main()
