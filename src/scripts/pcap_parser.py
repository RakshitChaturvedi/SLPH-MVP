import sys
from scapy.all import rdpcap, TCP, UDP, Raw
from typing import List, Dict

def extract_payloads(pcap_path: str) -> List[Dict[str, str]]:
    """ Parses a PCAP file and extracts application-layer payloads from TCP
        and UDP packets.

        Args:
            pcap_path (str): The file path to the .pcap or .pcapng file.

        Returns:
            list: A list of bytes, where each element is a raw payload from 
                  a packet.
                  Returns an empty list if the file can't be read or contains
                  no relevant packets.
    """

    payloads = []
    try:
        packets = rdpcap(pcap_path)
    except FileNotFoundError:
        print(f"Error: File not found at '{pcap_path}'")
        return []
    except Exception as e:
        print(f"An error occured while reading the file: {e}")
        return []
    
    for packet in packets:
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            # payload is the data that comes after TCP/UDP header.
            if packet.haslayer(Raw):
                # extract raw bytes of the payload.
                payload_bytes = packet[Raw].load
                if payload_bytes:
                    decoded_string = payload_bytes.decode('utf-8', errors='ignore')
                    payloads.append({
                        "payload_hex": payload_bytes.hex(),
                        "payload_string": decoded_string
                    })
    
    return payloads

def main():
    """ Handles command-line args and runs the extraction.
    """
    # Check if cl arg (file-path) is provided
    if len(sys.argv) != 2:
        print("Usage: python pcap_parser.py <path_to_pcap_file>")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    print(f"[*] Parsing '{pcap_file}'...")

    extracted_payloads = extract_payloads(pcap_file)

    if not extracted_payloads:
        print("[!] No application-layer payloads found or file could not be read.")
        return
    
    print(f"\n[*] Found {len(extracted_payloads)} payloads.\n")

    for i, payload_data in enumerate(extracted_payloads):
        payload_len = len(bytes.fromhex(payload_data['payload_hex']))
        print(f"--- Payload {i+1} ({payload_len} bytes) ---")
        print(payload_data['payload_string'])
        print("-" * (len(f"--- Payload {i+1} ({payload_len} bytes) ---")) + "\n")
    
if __name__ == "__main__":
    main()