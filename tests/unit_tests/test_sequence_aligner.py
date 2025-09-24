import unittest
import sys
import os
from unittest.mock import patch, MagicMock

# --- Test Environment Setup ---
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.insert(0, project_root)

from src.scripts.sequence_aligner import align_sequences
from tests.test_mock_data import get_mock_message_groups

class TestSequenceAligner(unittest.TestCase):
    """
    Test suite for the sequence alignment script.
    """

    def setUp(self):
        """
        Set up mock data by importing it from the central mock_data module.
        """
        self.mock_group_a, _ = get_mock_message_groups()

    @patch('src.scripts.sequence_aligner.subprocess.run')
    def test_successful_alignment(self, mock_subprocess_run):
        """
        Verify that the script correctly calls MAFFT and parses its output.
        The subprocess call is mocked to make the test fast and independent.
        """
        print("\n[*] Testing successful alignment and parsing...")

        # --- THIS IS THE FIX: A perfect, predictable mock of MAFFT's output ---
        # A real alignment would show the last two characters as variable.
        static_part = 'aabb' * 20
        mock_mafft_output = f""">msg_0
{static_part}00
>msg_1
{static_part}01
>msg_2
{static_part}02
>msg_3
{static_part}03
>msg_4
{static_part}04
>msg_5
{static_part}05
>msg_6
{static_part}06
>msg_7
{static_part}07
"""
        # Configure the mock to return our perfect stdout
        mock_process = MagicMock()
        mock_process.stdout = mock_mafft_output
        mock_subprocess_run.return_value = mock_process

        # Run the function we are testing
        result = align_sequences(self.mock_group_a)

        # --- THIS IS THE FIX: The expected structure now perfectly matches the mock ---
        expected_structure = [
            {'type': 'static', 'hex_value': static_part},
            {'type': 'variable', 'length': 1} # The last byte (2 hex chars) is variable
        ]

        self.assertIsNotNone(result, "Result should not be None.")
        self.assertListEqual(result, expected_structure, "The parsed structure is incorrect.")
        
        mock_subprocess_run.assert_called_once()
        print("[+] Success test passed for alignment.")

    def test_empty_input(self):
        """Verify that the script handles empty input gracefully."""
        print("\n[*] Testing alignment with empty input...")
        result = align_sequences([])
        self.assertEqual(result, [])
        print("[+] Empty input test passed.")

    def test_single_message_input(self):
        """Verify that the script skips alignment for a single message."""
        print("\n[*] Testing alignment with a single message...")
        result = align_sequences([self.mock_group_a[0]])
        self.assertEqual(result, [])
        print("[+] Single message test passed.")

if __name__ == '__main__':
    unittest.main()
