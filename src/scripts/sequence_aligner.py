import sys
import subprocess
import argparse
import tempfile
import os
from typing import List, Dict, Any

try:
    from message_clusterer import cluster_messages
    from pcap_parser import extract_payloads
except ImportError:
    from src.scripts.message_clusterer import cluster_messages
    from src.scripts.pcap_parser import extract_payloads

def _messages_to_fasta(messages: List[Dict[str, Any]]) -> str:
    """ Converts a list of message payloads into 
        standard, line-wrapped FASTA format string.
    """
    fasta_entries = []
    for i, msg in enumerate(messages):
        sequence = msg['payload_hex']
        wrapped_sequence = "\n".join([
            sequence[j:j+80] for j in range(0, len(sequence), 80)
        ])
        fasta_entries.append(f">msg_{i}\n{wrapped_sequence}")
    return "\n".join(fasta_entries)

def _parse_mafft_output(output: str) -> Dict[str, str]:
    """ Parses aligned FASTA o/p from MAFFT.
    """
    aligned_sequences = {}
    current_msg_id = None
    current_sequence = []

    for line in output.strip().split('\n'):
        if line.startswith(">"):
            # if building a sequence, save it before starting new one.            
            if current_msg_id and current_sequence:
                aligned_sequences[current_msg_id] = "".join(current_sequence)
            
            # start new sequence
            current_msg_id = line[1:].strip()
            current_sequence = []
        else:
            if current_msg_id:
                current_sequence.append(line.strip())
    
    # save the very last sequence in file
    if current_msg_id and current_sequence:
        aligned_sequences[current_msg_id] = "".join(current_sequence)
    
    return aligned_sequences

def _identify_regions(aligned_sequences: Dict[str, str]) -> List[Dict[str, Any]]:
    """ Analyzes the aligned sequences col by col 
        to identify static and variable regions,
        correctly handling alignment gaps ('-')
    """
    if not aligned_sequences: return []

    sequences = list(aligned_sequences.values())
    if not sequences or not all(len(s) == len(sequences[0]) for s in sequences):
        return []
    
    alignment_length = len(sequences[0])
    protocol_structure = []

    i = 0
    while i < alignment_length:
        # handle potential alignment gaps and misalign bytes
        if sequences[0][i] == '-':
            i += 1
            continue

        # ensure we have full byte to read
        if i+1 >= alignment_length:
            break

        byte_column = {seq[i:i+2] for seq in sequences}
        is_static = len(byte_column) == 1 and '-' not in list(byte_column)[0]

        if is_static:
            current_byte = list(byte_column)[0]
            # If the last region was also static, merge with it
            if protocol_structure and protocol_structure[-1]['type'] == 'static':
                protocol_structure[-1]['hex_value'] += current_byte
            else:
                protocol_structure.append({'type': 'static', 'hex_value': current_byte})
        else: # Variable byte
            # If the last region was also variable, merge with it
            if protocol_structure and protocol_structure[-1]['type'] == 'variable':
                protocol_structure[-1]['length'] += 1
            else:
                protocol_structure.append({'type': 'variable', 'length': 1})
        i+=2

    return protocol_structure

def align_sequences(messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """ Performs MSA using MAFFT
    """
    if not messages or len(messages) < 2:
        return []
    
    fasta_input = _messages_to_fasta(messages)

    with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix=".fasta") as temp_input_file:
        temp_input_file.write(fasta_input)
        temp_input_filepath = temp_input_file.name

    try:
        print("[*] Running MAFFT for sequence alignment...")

        # MAFFT takes i/p file as main arguement
        command = [
            'mafft',
            '--quiet',
            temp_input_filepath
        ]
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True,
        )
    except FileNotFoundError:
        print("\n[-] FATAL ERROR: 'mafft' command not found.", file=sys.stderr)
        print("    Please install MAFFT.", file=sys.stderr)
        return []
    except subprocess.CalledProcessError as e:
        print(f"[-] Error during MAFFT execution: {e.stderr}", file=sys.stderr)
        return []
    finally:
        if os.path.exists(temp_input_filepath):
            os.remove(temp_input_filepath)
    
    aligned_sequences = _parse_mafft_output(process.stdout)
    if not aligned_sequences:
        print("[-] Failed to parse MAFFT output.", file=sys.stderr)
        return []
    
    structure = _identify_regions(aligned_sequences)
    return structure

def main():
    parser = argparse.ArgumentParser(description="Align message payloads from a PCAP file using MAFFT.")
    parser.add_argument("pcap_path", help="Path to the PCAP file.")
    parser.add_argument("--n-clusters", type=int, default=10, help="Number of clusters to find.")
    args = parser.parse_args()

    payloads = extract_payloads(args.pcap_path)
    if not payloads: print("[!] No payloads found."); sys.exit(1)
        
    clustered_messages = cluster_messages(payloads, n_clusters=args.n_clusters)
    if not clustered_messages: print("[!] Clustering failed."); sys.exit(1)
    
    eligible_clusters = {k: v for k, v in clustered_messages.items() if len(v) > 1}
    if not eligible_clusters: print("[!] No clusters for alignment found."); sys.exit(1)

    largest_cluster_id = max(eligible_clusters, key=lambda k: len(eligible_clusters[k]))
    cluster_to_align = eligible_clusters[largest_cluster_id]
    print(f"\n[*] Aligning largest cluster (ID: {largest_cluster_id}) with {len(cluster_to_align)} messages.")
    
    protocol_structure = align_sequences(cluster_to_align)
    
    if protocol_structure:
        print("\n--- Inferred Protocol Structure ---")
        for region in protocol_structure:
            print(f"  [{region['type'].upper():<8}] ", end="")
            if region['type'] == 'static': print(f"Hex: {region['hex_value']}")
            else: print(f"Length: {region['length']} bytes")
        print("-----------------------------------")
    else:
        print("\n[!] Could not determine protocol structure."); sys.exit(1)

if __name__ == "__main__":
    main()