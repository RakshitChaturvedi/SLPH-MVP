import unittest
import os
import sys
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

from services.ingestion_service.main import app

class TestPersistenceApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """ Set up a temporary directory and the TestClient once for all tests.
        """
        cls.test_temp_dir = PROJECT_ROOT / "test_temp_uploads_persistence"
        os.environ["TEMP_UPLOADS_DIR"] = str(cls.test_temp_dir)
        cls.test_temp_dir.mkdir(exist_ok=True)
        cls.client = TestClient(app)
    
    @classmethod
    def tearDownClass(cls):
        """ Clean up the temporary directory after all tests are done.
        """
        if cls.test_temp_dir.exists():
            shutil.rmtree(cls.test_temp_dir)
        if "TEMP_UPLOADS_DIR" in os.environ:
            del os.environ["TEMP_UPLOADS_DIR"]
        
    @patch('services.ingestion_service.main.projects_collection')
    @patch('services.ingestion_service.main.minio_client')
    def test_persistence_workflow_with_pcap(self, mock_minio_client, mock_mongo_collection):
        """ Test full upload-and-persist workflow for PCAP file.
        """
        print("\n[*] Testing persistence workflow with PCAP file...")
        mock_insert_result = MagicMock()
        mock_insert_result.inserted_id = ObjectId()
        mock_mongo_collection.insert_one.return_value = mock_insert_result

        dummy_pcap_path = self.test_temp_dir / "test.pcap"
        test_packet = Ether()/IP(dst="8.8.8.8")/TCP()/"test"
        wrpcap(str(dummy_pcap_path), [test_packet])
        
        with open(dummy_pcap_path, "rb") as f:
            response = self.client.post("/upload", files={"file": ("test.pcap", f, "application/octet-stream")})

        self.assertEqual(response.status_code, 200)
        mock_minio_client.fput_object.assert_called_once()
        mock_mongo_collection.insert_one.assert_called_once()
        
        inserted_document = mock_mongo_collection.insert_one.call_args[0][0]
        self.assertEqual(inserted_document['analysis_type'], 'pcap')

        print("[+] PCAP persistence test passed.")
        os.remove(dummy_pcap_path)

    @patch('services.ingestion_service.main.projects_collection')
    @patch('services.ingestion_service.main.minio_client')
    def test_persistence_workflow_with_binary(self, mock_minio_client, mock_mongo_collection):
        """ Tests the full upload-and-persist workflow for a binary file.
        """
        print("\n[*] Testing persistence workflow with Binary file...")
        mock_insert_result = MagicMock()
        mock_insert_result.inserted_id = ObjectId()
        mock_mongo_collection.insert_one.return_value = mock_insert_result

        binary_path = "/bin/true" # A common, small, safe executable
        
        with open(binary_path, "rb") as f:
            response = self.client.post("/upload", files={"file": ("true_executable", f, "application/octet-stream")})

        self.assertEqual(response.status_code, 200)
        mock_minio_client.fput_object.assert_called_once()
        mock_mongo_collection.insert_one.assert_called_once()
        
        inserted_document = mock_mongo_collection.insert_one.call_args[0][0]
        self.assertEqual(inserted_document['project_name'], 'true_executable')
        self.assertEqual(inserted_document['analysis_type'], 'binary')
        self.assertEqual(inserted_document['metadata']['format'], 'ELF')

        print("[+] Binary persistence test passed.")

if __name__ == "__main__":
    unittest.main()