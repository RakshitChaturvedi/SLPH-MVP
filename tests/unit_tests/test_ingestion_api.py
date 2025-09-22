import unittest
import os
import sys
import shutil
from pathlib import Path
from fastapi.testclient import TestClient

TEST_DIR = Path(__file__).resolve().parent.parent
PROJECT_ROOT = TEST_DIR.parent
sys.path.insert(0, str(PROJECT_ROOT))

from services.ingestion_service.main import app, TEMP_UPLOADS_DIR

class TestIngestionApi(unittest.TestCase):
    
    def setUp(self):
        self.client = TestClient(app)

        self.dummy_file_path = "test_upload.pcap"
        with open(self.dummy_file_path, "wb") as f:
            f.write(b"This is a dummy pcap file.")
    
    def tearDown(self):
        if os.path.exists(self.dummy_file_path):
            os.remove(self.dummy_file_path)

        uploaded_file = TEMP_UPLOADS_DIR / self.dummy_file_path
        if os.path.exists(uploaded_file):
            os.remove(uploaded_file)
    
    def test_successful_file_upload(self):
        print("\n[*] Testing API endpoint: POST /upload...")

        with open(self.dummy_file_path, "rb") as f:
            response = self.client.post("/upload", files={"file": (self.dummy_file_path, f, "application/octet-stream")})
        
        self.assertEqual(response.status_code, 200)

        response_json = response.json()
        self.assertEqual(response_json["filename"], self.dummy_file_path)
        self.assertEqual(response_json["status"], "received")

        expected_file_path = TEMP_UPLOADS_DIR / self.dummy_file_path
        self.assertTrue(os.path.exists(expected_file_path))
        
        print("[+] API endpoint test passed.")

if __name__ == "__main__":
    unittest.main()
        