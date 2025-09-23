import unittest
import os
import sys
import json
import shutil
from pathlib import Path
from unittest.mock import patch, MagicMock

from fastapi.testclient import TestClient
from scapy.all import wrpcap, Ether, IP, TCP
from bson.objectid import ObjectId

# --- Test env setup ---
TEST_DIR = Path(__file__).resolve().parent.parent
PROJECT_ROOT = TEST_DIR.parent
sys.path.insert(0, str(PROJECT_ROOT))

from services.ingestion_service.main import app, CORRELATION_QUEUE

class TestIngestionService(unittest.TestCase):
    """ Test suite for the complete F-101 Ingestion Service workflow,
        including parsing, persistence, and task orchestration.
    """

    @classmethod
    def setUpClass(cls):
        # set up a temp directory and the TestClient once for all tests.
        cls.test_temp_dir = PROJECT_ROOT / "test_temp_uploads_final"
        os.environ["TEMP_UPLOADS_DIR"] = str(cls.test_temp_dir)
        cls.test_temp_dir.mkdir(exist_ok=True)
        cls.client = TestClient(app)

    @classmethod
    def tearDownClass(cls):
        # clean up the temp directory after all tests are done.
        if cls.test_temp_dir.exists():
            shutil.rmtree(cls.test_temp_dir)
        if "TEMP_UPLOADS_DIR" in os.environ:
            del os.environ["TEMP_UPLOADS_DIR"]

    # mock all three external service clients
    @patch('services.ingestion_service.main.app_state', new_callable=dict)
    def test_full_pcap_workflow(self, mock_app_state):
        """ Tests the full workflow: upload -> store -> publish task for a PCAP file.
        """
        print("\n[*] Testing full ingestion pipeline with PCAP...")

        # 1. Arrange: Configure all our mock clients
        mock_mongo_collection = MagicMock()
        mock_minio_client = MagicMock()
        mock_rabbitmq_channel = MagicMock()

        # Set the mocks in our patched app_state dictionary
        mock_app_state['projects_collection'] = mock_mongo_collection
        mock_app_state['minio_client'] = mock_minio_client
        mock_app_state['rabbitmq_channel'] = mock_rabbitmq_channel
        
        # Simulate a successful database insert
        mock_insert_result = MagicMock()
        test_project_id = ObjectId()
        mock_insert_result.inserted_id = test_project_id
        mock_mongo_collection.insert_one.return_value = mock_insert_result

        # Create a dummy PCAP file
        dummy_pcap_path = self.test_temp_dir / "test.pcap"
        wrpcap(str(dummy_pcap_path), [Ether()/IP()/TCP()/"test"])
        
        # 2. Act: Make the API request
        with open(dummy_pcap_path, "rb") as f:
            response = self.client.post("/upload", files={"file": ("test.pcap", f)})

        # 3. Assert: Verify the entire outcome
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['status'], 'processing_queued')
        
        # Verify persistence calls
        mock_minio_client.fput_object.assert_called_once()
        mock_mongo_collection.insert_one.assert_called_once()
        
        # Verify the RabbitMQ publish call (the new part)
        mock_rabbitmq_channel.basic_publish.assert_called_once()
        
        # Deeply inspect the arguments of the publish call
        publish_args = mock_rabbitmq_channel.basic_publish.call_args.kwargs
        self.assertEqual(publish_args['exchange'], '')
        self.assertEqual(publish_args['routing_key'], CORRELATION_QUEUE)
        
        # Parse the message body and check its content
        message_body = json.loads(publish_args['body'])
        self.assertEqual(message_body['task'], 'CorrelationTask')
        self.assertEqual(message_body['project_id'], str(test_project_id))

        print("[+] Full ingestion pipeline test passed.")
        os.remove(dummy_pcap_path)

if __name__ == "__main__":
    unittest.main()