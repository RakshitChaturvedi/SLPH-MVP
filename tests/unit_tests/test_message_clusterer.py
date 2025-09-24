import unittest
import sys
import os
from unittest.mock import patch
import numpy as np # Import numpy

# --- Test Environment Setup ---
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.insert(0, project_root)

from src.scripts.message_clusterer import cluster_messages, MIN_MESSAGES_FOR_LDA
from tests.test_mock_data import get_mock_message_groups

class TestMessageClusterer(unittest.TestCase):
    def setUp(self):
        self.mock_group_a_messages, self.mock_group_b_messages = get_mock_message_groups()
        self.large_mixed_messages = self.mock_group_a_messages + self.mock_group_b_messages
        self.small_message_set = self.large_mixed_messages[:5]

    @patch('src.scripts.message_clusterer.LatentDirichletAllocation')
    def test_successful_clustering_with_mock(self, mock_lda):
        print("\n[*] Testing successful clustering...")
        
        mock_model_instance = mock_lda.return_value
        mock_distributions = [[1.0, 0.0]] * 8 + [[0.0, 1.0]] * 8
        # --- THIS IS THE FIX: Return a real numpy array ---
        mock_model_instance.fit_transform.return_value = np.array(mock_distributions)
        
        result = cluster_messages(self.large_mixed_messages, n_clusters=2)

        self.assertIsNotNone(result)
        self.assertEqual(len(result), 2)
        print("[+] Success test passed for clustering.")

    def test_small_sample_size_override(self):
        print(f"\n[*] Testing small sample override...")
        result = cluster_messages(self.small_message_set, n_clusters=5)
        self.assertEqual(len(result), 1)
        print("[+] Small sample test passed.")

    def test_empty_input(self):
        print("\n[*] Testing handling of empty input...")
        result = cluster_messages([])
        self.assertEqual(len(result), 0)
        print("[+] Empty input test passed.")

if __name__ == '__main__':
    unittest.main()