import unittest
import os
import sys
import shutil
from pathlib import Path
from fastapi.testclient import TestClient
from scapy.all import wrpcap, Ether, IP, TCP, Raw
from services.ingestion_service.main import app

# --- Test Env Setup ---
TEST_DIR = Path(__file__).resolve().parent.parent
PROJECT_ROOT = TEST_DIR.parent
SRC_PATH = PROJECT_ROOT / "src"
SERVICES_PATH = PROJECT_ROOT / "services"
sys.path.insert(0, str(SRC_PATH))
sys.path.insert(0, str(SERVICES_PATH))

class TestIngestionApiLogic(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """ Setup a temp directory for all tests in this class.
        """
        cls.test_temp_dir = PROJECT_ROOT / "test_temp_uploads_api_logic"
        os.environ["TEMP_UPLOADS_DIR"] = str(cls.test_temp_dir)
        cls.test_temp_dir.mkdir(exist_ok=True)
        cls.client = TestClient(app)
    
    @classmethod
    def tearDownClass(cls):
        """ Clean up the temp directory after all tests are done.
        """
        if cls.test_temp_dir.exists():
            shutil.rmtree(cls.test_temp_dir)
        del os.environ["TEMP_UPLOADS_DIR"]
    
    def test_pcap_upload_succeeds(self):
        """ Verify that uploading a valid PCAP file returns parsed payload data.
        """

        print("\n[*] Testing API endpoint with valid PCAP file...")
        dummy_pcap_path = self.test_temp_dir / "test.pcap"

        # Create simple pcap file with one packet containing a payload
        test_packet = Ether()/IP(dst="8.8.8.8")/TCP()/"GET / HTTP/1.0\r\n\r\n"
        wrpcap(str(dummy_pcap_path), [test_packet])

        with open(dummy_pcap_path,"rb") as f:
            response = self.client.post("/upload", files={"file": ("test.pcap", f, "application/octet-stream")})

        # 1. check for success status
        self.assertEqual(response.status_code, 200)

        # 2. check that response is a list
        response_data = response.json()
        self.assertIsInstance(response_data, list)
        self.assertEqual(len(response_data), 1)

        # 3. check content of parsed data
        payload = response_data[0]
        self.assertIn("payload_hex", payload)
        self.assertIn("payload_string", payload)
        self.assertEqual(payload["payload_string"], "GET / HTTP/1.0\r\n\r\n")

        print("[+] PCAP upload test passed.")
        os.remove(dummy_pcap_path)

    def test_binary_upload_succeeds(self):
        """ Verify that uploading a valid binary file returns parsed metadata.
            use /bin/true as it's a small, safe, and standard ELF binary.
        """
        print("\n[*] Testing API endpoint with valid ELF binary file...")
        binary_path = "/bin/true"
        
        with open(binary_path, "rb") as f:
            response = self.client.post("/upload", files={"file": ("true_binary", f, "application/octet-stream")})

        # 1. Check for success status
        self.assertEqual(response.status_code, 200)

        # 2. Check that the response is a dict (from parse_binary)
        response_data = response.json()
        self.assertIsInstance(response_data, dict)
        
        # 3. Check for key metadata fields
        self.assertIn("format", response_data)
        self.assertIn("sections", response_data)
        self.assertIn("functions", response_data)
        self.assertEqual(response_data["format"], "ELF")

        print("[+] Binary upload test passed.")

    def test_invalid_file_fails(self):
        """ Verify that uploading an unsupported file returns a 400 error.
        """
        print("\n[*] Testing API endpoint with invalid file type...")
        dummy_txt_path = self.test_temp_dir / "invalid.txt"
        dummy_txt_path.write_text("This is not a valid file for parsing.")

        with open(dummy_txt_path, "rb") as f:
            response = self.client.post("/upload", files={"file": ("invalid.txt", f, "text/plain")})

        # 1. Check correct error status code
        self.assertEqual(response.status_code, 400)

        # 2. Check specific error message
        response_data = response.json()
        self.assertIn("detail", response_data)
        self.assertEqual(response_data["detail"], "Unsupported or invalid file format. Could not parse as PCAP or Binary.")

        print("[+] Invalid file test passed.")
        os.remove(dummy_txt_path)

if __name__ == "__main__":
    unittest.main()
