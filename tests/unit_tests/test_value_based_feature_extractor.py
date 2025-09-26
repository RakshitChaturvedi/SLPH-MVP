import unittest
import sys
import os

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.insert(0, project_root)

from src.scripts.feature_extractor import (
    calculate_shannon_entropy,
    calculate_cardinality,
    calculate_correlation,
    check_session_constancy,
    extract_value_based_features
)

class TestValueBasedFeatureExtractor(unittest.TestCase):

    def test_calculate_cardinality(self):
        self.assertEqual(calculate_cardinality([1, 1, 2, 3, 3, 3]), 3)
        self.assertEqual(calculate_cardinality(['a', 'b', 'a']), 2)
        self.assertEqual(calculate_cardinality([]), 0)

    def test_calculate_shannon_entropy(self):
        # Zero entropy (no uncertainty)
        self.assertAlmostEqual(calculate_shannon_entropy([1, 1, 1, 1]), 0.0)
        # Max entropy for 4 outcomes (high uncertainty)
        self.assertAlmostEqual(calculate_shannon_entropy([1, 2, 3, 4]), 2.0)
        # Mixed
        self.assertAlmostEqual(calculate_shannon_entropy([1, 1, 2, 2]), 1.0)
        self.assertEqual(calculate_shannon_entropy([]), 0.0)

    def test_calculate_correlation(self):
        # Perfect positive correlation
        self.assertAlmostEqual(calculate_correlation([1, 2, 3], [10, 20, 30]), 1.0)
        # Perfect negative correlation
        self.assertAlmostEqual(calculate_correlation([1, 2, 3], [30, 20, 10]), -1.0)
        # No correlation
        self.assertAlmostEqual(calculate_correlation([1, 1, 1], [10, 20, 30]), 0.0)
        # Edge case: empty list
        self.assertEqual(calculate_correlation([], []), 0.0)

    def test_check_session_constancy(self):
        # True session identifier
        self.assertTrue(check_session_constancy(
            field_values=[10, 10, 20, 20],
            session_ids=['A', 'A', 'B', 'B']
        ))
        # False: value is constant everywhere
        self.assertFalse(check_session_constancy(
            field_values=[10, 10, 10, 10],
            session_ids=['A', 'A', 'B', 'B']
        ))
        # False: value varies within a session
        self.assertFalse(check_session_constancy(
            field_values=[10, 11, 20, 20],
            session_ids=['A', 'A', 'B', 'B']
        ))
        # False: only one session
        self.assertFalse(check_session_constancy(
            field_values=[10, 10],
            session_ids=['A', 'A']
        ))

    def test_extract_value_based_features_orchestrator(self):
        mock_instances = [
            {'value': 8, 'message_length': 8, 'session_id': 'A'},
            {'value': 8, 'message_length': 8, 'session_id': 'A'},
            {'value': 16, 'message_length': 16, 'session_id': 'B'},
            {'value': 16, 'message_length': 16, 'session_id': 'B'},
        ]
        features = extract_value_based_features(mock_instances)
        
        self.assertEqual(features['cardinality'], 2)
        self.assertAlmostEqual(features['shannon_entropy'], 1.0)
        self.assertAlmostEqual(features['correlation_with_length'], 1.0)
        self.assertTrue(features['is_session_identifier'])

if __name__ == '__main__':
    unittest.main()