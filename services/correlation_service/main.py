import pika
import time
import os
import sys
import json
import subprocess
import tempfile
import traceback
from collections import Counter
from pathlib import Path
from pprint import pprint
from pymongo import MongoClient
from bson.objectid import ObjectId
from minio import Minio

# --- Path Setup ---
CURRENT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = CURRENT_DIR.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.scripts.pcap_parser import extract_payloads
from src.scripts.message_clusterer import cluster_messages
from src.scripts.sequence_aligner import align_sequences

# ... (Configuration constants are unchanged) ...
RABBITMQ_HOST = os.environ.get("RABBITMQ_HOST", "localhost")
CORRELATION_QUEUE = "correlation_task_queue"
MINIO_ENDPOINT = os.environ.get("MINIO_ENDPOINT", "localhost:9000")
MINIO_ACCESS_KEY = os.environ.get("MINIO_ACCESS_KEY", "minioadmin")
MINIO_SECRET_KEY = os.environ.get("MINIO_SECRET_KEY", "minioadmin")
MINIO_BUCKET = "slph-artifacts"
MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017/")
MONGO_DB_NAME = "slph_projects"

# --- Global service clients ---
mongo_client = None
minio_client = None
db_collection = None

def process_task(channel, method, properties, body):
    temp_dir = None
    tracer_process = None
    try:
        message = json.loads(body.decode())
        project_id = message.get("project_id")
        project_doc = db_collection.find_one({"_id": ObjectId(project_id)})
        temp_dir = tempfile.TemporaryDirectory()
        pcap_object_name = project_doc.get("pcap_object_name")
        binary_object_name = project_doc.get("binary_object_name")
        local_pcap_path = Path(temp_dir.name) / pcap_object_name
        local_binary_path = Path(temp_dir.name) / binary_object_name
        minio_client.fget_object(MINIO_BUCKET, pcap_object_name, str(local_pcap_path))
        minio_client.fget_object(MINIO_BUCKET, binary_object_name, str(local_binary_path))
        local_binary_path.chmod(0o755)

        # --- Network Analysis ---
        print("[*] Starting Network Analysis Pipeline...")
        payloads = extract_payloads(str(local_pcap_path))
        clusters = cluster_messages(payloads, n_clusters=10)
        all_aligned_structures = {}
        if clusters:
            for cluster_id, messages in clusters.items():
                if len(messages) < 2: continue
                aligned_structure = align_sequences(messages)
                all_aligned_structures[str(cluster_id)] = {"message_count": len(messages), "inferred_structure": aligned_structure}
        network_results = {"total_payloads": len(payloads), "analyzed_clusters": all_aligned_structures, "raw_payloads": payloads}
        print("[+] Network analysis complete.")

        # --- Binary Analysis with STABLE Tracer ---
        print("[*] Starting Binary Analysis Pipeline...")
        target_python_script = str(local_binary_path)
        trace_log_path = Path(temp_dir.name) / "trace.jsonl"
        frida_script_path = PROJECT_ROOT / 'tools' / 'fridatracer' / 'frida_tracer.py'
        frida_command = [
            sys.executable, str(frida_script_path), "--output", str(trace_log_path),
            "--", sys.executable, target_python_script
        ]
        
        tracer_process = subprocess.Popen(frida_command, stdout=subprocess.PIPE, text=True)
        
        ready = False
        for line in iter(tracer_process.stdout.readline, ''):
            if "---TRACER-READY---" in line:
                ready = True
                break
        if not ready: raise Exception("Tracer failed to start.")

        client_script_path = PROJECT_ROOT / 'test_artifacts' / 'echo_client.py'
        subprocess.run([sys.executable, str(client_script_path)], timeout=5, check=True)
        
        tracer_process.terminate()
        tracer_process.wait(timeout=5)

        # --- Parse STABLE Trace and Create Bag-of-Words ---
        instruction_mnemonics = []
        if trace_log_path.exists():
            with open(trace_log_path, 'r') as f:
                for line in f:
                    try:
                        trace = json.loads(line)
                        mnemonic = trace.get('mnemonic')
                        if mnemonic: instruction_mnemonics.append(mnemonic)
                    except (json.JSONDecodeError, IndexError): continue
        
        binary_results = {"mnemonic_counts": dict(Counter(instruction_mnemonics))}
        print(f"[+] Binary analysis complete. Found {len(instruction_mnemonics)} instructions.")
        pprint(binary_results)
        
        final_model = {"network_model": network_results, "binary_model": binary_results}
        db_collection.update_one(
            {"_id": ObjectId(project_id)},
            {"$set": {"inferred_protocol_model": final_model, "status": "analysis_complete"}}
        )
        print("[+] Full analysis run finished successfully.")
        channel.basic_ack(delivery_tag=method.delivery_tag)
    
    except Exception as e:
        print(f"[-] A critical error occurred: {e}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        if 'method' in locals() and method:
            channel.basic_ack(delivery_tag=method.delivery_tag)
    finally:
        if tracer_process and tracer_process.poll() is None:
            tracer_process.kill()
        if temp_dir:
            temp_dir.cleanup()

# ... (main worker loop is unchanged) ...
def main():
    global mongo_client, minio_client, db_collection
    print("[*] Correlation service worker starting...")
    mongo_client = MongoClient(MONGO_URI)
    db = mongo_client[MONGO_DB_NAME]
    db_collection = db["projects"]
    minio_client = Minio(
        MINIO_ENDPOINT, access_key=MINIO_ACCESS_KEY,
        secret_key=MINIO_SECRET_KEY, secure=False
    )
    connection = None
    while True:
        try:
            connection = pika.BlockingConnection(pika.ConnectionParameters(host=RABBITMQ_HOST))
            channel = connection.channel()
            channel.queue_declare(queue=CORRELATION_QUEUE, durable=True)
            channel.basic_qos(prefetch_count=1)
            channel.basic_consume(queue=CORRELATION_QUEUE, on_message_callback=process_task)
            print(f"[*] Waiting for tasks on queue '{CORRELATION_QUEUE}'.")
            channel.start_consuming()
        except pika.exceptions.AMQPConnectionError:
            time.sleep(5)
        except KeyboardInterrupt:
            if connection and connection.is_open: connection.close()
            if mongo_client: mongo_client.close()
            break

if __name__ == '__main__':
    main()
