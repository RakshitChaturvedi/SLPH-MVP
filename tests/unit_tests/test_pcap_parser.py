import unittest
import os
import sys
from scapy.all import wrpcap, IP, TCP, UDP, ARP, Raw, Ether

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.insert(0, project_root)

from src.scripts.pcap_parser import extract_payloads

class TestPcapParser(unittest.TestCase):
    def setUp(self):
        """ Run before each test.
            Sets up the necessary test files.
        """

        self.valid_pcap_path = "test_valid.pcap"
        self.irrelevant_pca_path = "test_irrevelevant.pcap"
        self.non_existent_path = "non_existent_file.pcap"

        # Create valid .pcap file with known payloads
        self.payload1 = b"Hello TCP"
        self.payload2 = b"Hello UDP"

        valid_packets = [
            IP(dst="8.8.8.8")/TCP()/Raw(load=self.payload1),
            IP(dst="8.8.8.8")/TCP()/Raw(load=self.payload2)
        ]
        wrpcap(self.valid_pcap_path, valid_packets)

        # Create .pcap file without relevant payloads
        irrelevant_packets = [
            Ether()/ARP(pdst="192.168.1.1")
        ]
        wrpcap(self.irrelevant_pca_path, irrelevant_packets)
    
    def tearDown(self):
        """ Run after each test.
            Cleans up the files created during setUp.
        """

        if os.path.exists(self.valid_pcap_path):
            os.remove(self.valid_pcap_path)
        if os.path.exists(self.irrelevant_pca_path):
            os.remove(self.irrelevant_pca_path)
    
    def test_successful_extraction(self):
        result = extract_payloads(self.valid_pcap_path)

        self.assertEqual(len(result), 2)
        self.assertIn(self.payload1, result)
        self.assertIn(self.payload2, result)

    def test_file_not_found(self):
        result = extract_payloads(self.non_existent_path)
        
        self.assertEqual(result, [])
    
    def test_pcap_with_no_payloads(self):
        result = extract_payloads(self.irrelevant_pca_path)

        self.assertEqual(result, [])

if __name__ == "__main__":
    unittest.main()