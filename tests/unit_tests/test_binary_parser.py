import unittest
import os
import sys
from pathlib import Path

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.insert(0, project_root)

from src.scripts.binary_parser import parse_binary

class TestBinaryParser(unittest.TestCase):

    def setUp(self):
        self.invalid_file_path = "test_dummy_file.txt"
        with open(self.invalid_file_path, "w") as f:
            f.write("This is not an executable file.")

        self.non_existent_file_path = "this_file_doesnt_exist.bin"

        self.valid_elf_path = "/bin/ls"
    
    def tearDown(self):
        if os.path.exists(self.invalid_file_path):
            os.remove(self.invalid_file_path)
    
    def test_successful_parsing_elf(self):
        print(f"\n[*] Testing successful parsing of '{self.valid_elf_path}'...")
        metadata = parse_binary(self.valid_elf_path)

        # 1. Check that result is not empty
        self.assertIsNotNone(metadata)
        self.assertIsInstance(metadata, dict)
        self.assertNotEqual(metadata, {})

        # 2. Check presence of top-level keys
        self.assertIn("file_path", metadata)
        self.assertIn("format", metadata)
        self.assertIn("sections", metadata)
        self.assertIn("functions", metadata)

        # 3. Check format and section structure
        self.assertEqual(metadata["format"], "ELF")
        self.assertIn("text", metadata["sections"])
        self.assertIn("data", metadata["sections"])

        # 4. Check that function list exists and is a list
        self.assertIsInstance(metadata["functions"], list)
        print("[+] Success test passed.")

    def test_file_not_found(self):
        print(f"\n[*] Testing handling of non-existent file...")
        metadata = parse_binary(self.non_existent_file_path)

        self.assertEqual(metadata, {})
        print("[+] File not found test passed.")
    
    def test_parsing_invalid_file(self):
        print(f"[*] Testing handling of invalid file format...")
        metadata = parse_binary(self.invalid_file_path)

        self.assertEqual(metadata, {})
        print("[+] Invalid file format test passed.")

if __name__ == '__main__':
    unittest.main()