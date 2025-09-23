import unittest
import sys
import os
from unittest.mock import patch
from sklearn.cluster import KMeans
from sklearn.feature_extraction.text import CountVectorizer

# --- Test Environment Setup ---
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.insert(0, project_root)

from src.scripts.message_clusterer import cluster_messages, MIN_MESSAGES_FOR_LDA

# --- This is the new, intelligent mock function ---
def mock_lda_with_kmeans(n_components, **kwargs):
    """
    A mock factory that intercepts the creation of LatentDirichletAllocation
    and returns a deterministic KMeans instance instead. It correctly maps
    the 'n_components' argument from LDA to the 'n_clusters' argument
    required by KMeans.
    """
    # Create a KMeans instance with parameters that ensure deterministic behavior
    return KMeans(
        n_clusters=n_components,
        random_state=kwargs.get('random_state', 42), # Use random_state if provided
        init='k-means++',
        n_init='auto'
    )

class TestMessageClusterer(unittest.TestCase):
    """
    Test suite for the message clustering script.
    """

    def setUp(self):
        """
        Set up robust mock data to ensure a strong, clear signal for clustering.
        """
        self.mock_group_a_messages = []
        for i in range(8):
            payload_hex = ('aabb' * 20) + f"{i:02x}" # Use 2-digit hex
            self.mock_group_a_messages.append({
                'payload_hex': payload_hex,
                'payload_string': f'GROUP_A_PKT_{i}'
            })

        self.mock_group_b_messages = []
        for i in range(8):
            payload_hex = ('ccdd' * 20) + f"{i:02x}" # Use 2-digit hex
            self.mock_group_b_messages.append({
                'payload_hex': payload_hex,
                'payload_string': f'GROUP_B_PKT_{i}'
            })
        
        self.large_mixed_messages = self.mock_group_a_messages + self.mock_group_b_messages
        self.small_message_set = self.large_mixed_messages[:5]

    # Patch the LDA class with our custom mock factory function
    @patch('src.scripts.message_clusterer.LatentDirichletAllocation', mock_lda_with_kmeans)
    def test_successful_clustering_with_mock(self):
        """
        Verify correct grouping using a deterministic mock. The @patch decorator
        replaces the LDA class with our mock_lda_with_kmeans function,
        ensuring a stable and predictable test outcome.
        """
        print("\n[*] Testing successful clustering with a deterministic mock...")
        
        result = cluster_messages(self.large_mixed_messages, n_clusters=2)

        # --- Assertions ---
        self.assertIsNotNone(result)
        self.assertEqual(len(result), 2, "Should find exactly two clusters.")

        total_messages_in_clusters = sum(len(msgs) for msgs in result.values())
        self.assertEqual(total_messages_in_clusters, len(self.large_mixed_messages))

        # Extract the sets of strings for comparison
        cluster_contents = [
            {msg['payload_string'] for msg in messages}
            for messages in result.values()
        ]
        group_a_strings = {msg['payload_string'] for msg in self.mock_group_a_messages}
        group_b_strings = {msg['payload_string'] for msg in self.mock_group_b_messages}

        # Verify that the two clusters contain the two groups of messages
        self.assertTrue(
            (cluster_contents[0] == group_a_strings and cluster_contents[1] == group_b_strings) or
            (cluster_contents[0] == group_b_strings and cluster_contents[1] == group_a_strings),
            "Clusters should perfectly separate Group A and Group B messages."
        )
        print("[+] Success test passed.")

    def test_small_sample_size_override(self):
        print(f"\n[*] Testing small sample override (less than {MIN_MESSAGES_FOR_LDA} messages)...")
        result = cluster_messages(self.small_message_set, n_clusters=5)
        self.assertEqual(len(result), 1)
        self.assertIn(0, result)
        self.assertEqual(len(result[0]), len(self.small_message_set))
        self.assertCountEqual([m['payload_string'] for m in result[0]], [m['payload_string'] for m in self.small_message_set])
        print("[+] Small sample test passed.")

    def test_empty_input(self):
        print("\n[*] Testing handling of empty input...")
        result = cluster_messages([])
        self.assertIsInstance(result, dict)
        self.assertEqual(len(result), 0)
        print("[+] Empty input test passed.")

if __name__ == '__main__':
    unittest.main()