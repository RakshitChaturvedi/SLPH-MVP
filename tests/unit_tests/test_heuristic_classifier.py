import unittest
import sys
import os

# --- Path Setup ---
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.insert(0, project_root)

from src.scripts.heuristic_classifier import classify_field_heuristically

class TestHeuristicClassifier(unittest.TestCase):

    def test_classify_length_field(self):
        # High correlation should be classified as LENGTH
        features = {"value_based": {"correlation_with_length": 0.98}}
        field_def = {"offset": 0, "length": 2}
        result = classify_field_heuristically(features, field_def, [])
        self.assertEqual(result, "LENGTH")

    def test_classify_session_id_field(self):
        # is_session_identifier being True should classify as SESSION_ID
        features = {"value_based": {"is_session_identifier": True, "correlation_with_length": 0.1}}
        field_def = {"offset": 4, "length": 4}
        result = classify_field_heuristically(features, field_def, [])
        self.assertEqual(result, "SESSION_ID")

    def test_classify_command_id_field(self):
        # Low cardinality and low offset should classify as COMMAND_ID
        features = {"value_based": {"cardinality": 5, "is_session_identifier": False, "correlation_with_length": 0.1}}
        field_def = {"offset": 1, "length": 1} # At the start of the message
        result = classify_field_heuristically(features, field_def, [])
        self.assertEqual(result, "COMMAND_ID")
        
        # Should fail if offset is high
        field_def_high_offset = {"offset": 20, "length": 1}
        result_high_offset = classify_field_heuristically(features, field_def_high_offset, [])
        self.assertEqual(result_high_offset, "UNKNOWN")

    def test_classify_unknown_field(self):
        # Generic features should result in UNKNOWN
        features = {"value_based": {"cardinality": 150, "is_session_identifier": False, "correlation_with_length": 0.3}}
        field_def = {"offset": 10, "length": 8}
        result = classify_field_heuristically(features, field_def, [])
        self.assertEqual(result, "UNKNOWN")

if __name__ == '__main__':
    unittest.main()