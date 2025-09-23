import sys
import argparse
import string
from typing import List, Dict, Any
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.decomposition import LatentDirichletAllocation

# to allow running this script directly and importing from parent directory
try:
    from pcap_parser import extract_payloads
except ImportError:
    from src.scripts.pcap_parser import extract_payloads

MIN_MESSAGES_FOR_LDA = 10

def make_printable(payload_string: str) -> str:
    return "".join(char if char in string.printable and not char.isspace() else '.' for char in payload_string)

def cluster_messages(
        messages: List[Dict[str, Any]],
        n_clusters: int = 5,
        n_gram_size: int = 2,
) -> Dict[int, List[Dict[str, Any]]]:
    """ Groups raw message payloads into clusters based on their content using LDA.

        It's the first step in network trace analysis, designed to group messages by
        their likely type before further processing like MSA. 

        Uses a "bag of n-grams" approach to vectorize message payloads and then
        applies LDA (Latent Dirichlet Allocation) to discover latent topics, which
        correspond to message types.

        Args:
            messages:   A list of message dicts, where each dict is expected to 
                        have a 'payload_hex' key. This is the format produced
                        by the pcap_parser.py script.
            n_clusters: The number of distinct message types (topics) to find.
                        This may require tuning depending on the protocol.
            n_gram_size: The size of byte sequencs to use as features.
                         Bigrams (2) are generally a good starting point.
        
        Returns:
            A dict where keys are cluster IDs (int) and values are lists of
            the original message dictionaries belonging to that cluster.

            Returns an empty dict if input is empty or clustering fails.
    """

    if not messages:
        print("[-] Input message list is empty. Cannot perform clustering.", file=sys.stderr)
        return {}
    
    # if too few messages, LDA fails due to data sparsity.
    if len(messages) < MIN_MESSAGES_FOR_LDA:
        print(
            f"[-] Warning: Only {len(messages)} messages found, which is below the "
            f"threshold of {MIN_MESSAGES_FOR_LDA} for reliable LDA clustering.",
            file=sys.stderr
        )
        print("[+] Assigning all messages to a single cluster (ID 0).")
        return {0: messages}
    
    # If fewer mssgs than requested clusters, LDA fails.
    effective_n_clusters = min(n_clusters, len(messages))

    if effective_n_clusters <= 1:
        print("[+] Only one group of messages found. Assigning all to cluster 0.")
        return {0: messages}
    
    # 1. Preprocess payloads for vectorization
    # treat hex representation as a document and each byte-pair as word
    hex_payloads = [" ".join(
        [msg['payload_hex'][i:i+2] for i in range(0, len(msg['payload_hex']), 2)]
    ) for msg in messages ]

    print(f"[*] Vectorizing {len(hex_payloads)} messages using byte {n_gram_size}-grams...")

    # 2. Vectorize the message payloads using bag of n grams model.
    try:
        # define a token_pattern to ensure it captures 2-character hex codes.
        # this creates a matrix where rows are messages, cols are n-gram counts.
        vectorizer = CountVectorizer(
            ngram_range=(n_gram_size, n_gram_size),
            token_pattern=r"(?u)\b\w\w\b"
        )

        X = vectorizer.fit_transform(hex_payloads)
    except Exception as e:
        print(f"[-] Error during vectorization: {e}", file=sys.stderr)
        return {}
    
    # 3. Apply LDA to discover topics (aka clusters)
    print(f"[*] Applying LDA to find {effective_n_clusters} clusters...")

    lda = LatentDirichletAllocation(
        n_components = effective_n_clusters,
        random_state = 42, # life, amiright? ;)
        n_jobs=-1
    )
    # trains model and assigns topic to each message.
    try:
        topic_distributions = lda.fit_transform(X)
    except Exception as e:
        print(f"[-] Error during LDA fitting: {e}", file=sys.stderr)
    # find most likely model for each mssg. (highest prob)
    message_topics = topic_distributions.argmax(axis=1)

    # 4. Group original messages by their assigned cluster ID.
    clusters: Dict[int, List[Dict[str, Any]]] = {}
    for i, msg in enumerate(messages):
        cluster_id = message_topics[i]
        # setdefault initializes the list if key doesnt exist yet.
        clusters.setdefault(cluster_id, []).append(msg)
    
    print(f"[+] Clustering complete. Found {len(clusters)} distinct groups.")
    return clusters

def main():
    """ to run the script from cmdline.
        takes a pcap file, parses it, clusters the messages, prints the results.
    """
    
    parser = argparse.ArgumentParser(
        description="Parse a PCAP file and cluster it's application-layer message"
    )
    parser.add_argument(
        "pcap_path",
        help="The file path to the .pcap or .pcapng file."
    )
    parser.add_argument(
        "--n-clusters",
        type=int,
        default=5,
        help="The number of clusters (message types) to identify."
    )
    args = parser.parse_args()

    print(f"[*] Reading payloads from '{args.pcap_path}'...")
    payloads = extract_payloads(args.pcap_path)

    if not payloads:
        print("[!] No application-layer payloads found. Exiting.")
        sys.exit(0)
    
    print(f"[*] Found {len(payloads)} payloads.")
    clustered_messages = cluster_messages(payloads, n_clusters=args.n_clusters)
    
    if not clustered_messages:
        print("[!] Clustering failed.")
        sys.exit(1)
    
    print("\n--- Clustering Results ---")
    for cluster_id, messages in sorted(clustered_messages.items()):
        print(f"\n[ Cluster {cluster_id} ] - {len(messages)} messages")
        print("-"*(14+len(str(cluster_id))))
        for msg in messages:
            hex_snippet = msg['payload_hex'][:40] # Show first 20 bytes
            printable_snippet = make_printable(msg['payload_string'])[:40]
            
            # Pad the snippets for clean alignment
            hex_padded = hex_snippet.ljust(40)
            printable_padded = printable_snippet.ljust(40)
            
            print(f"  -> Hex: {hex_padded} | Printable: {printable_padded}")
    print("\n--------------------")

if __name__ == "__main__":
    main()

    