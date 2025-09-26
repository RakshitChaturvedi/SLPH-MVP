import pika
import time
import os
import sys
import json
import subprocess
import tempfile

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

# --- RabbitMQ Config ---
RABBITMQ_HOST = os.environ.get("RABBITMQ_HOST", "localhost")
CORRELATION_QUEUE = "correlation_task_queue"

# --- MinIO Setup ---
MINIO_ENDPOINT = os.environ.get("MINIO_ENDPOINT", "localhost:9000")
MINIO_ACCESS_KEY = os.environ.get("MINIO_ACCESS_KEY", "minioadmin")
MINIO_SECRET_KEY = os.environ.get("MINIO_SECRET_KEY", "minioadmin")
MINIO_BUCKET = "slph-artifacts"

# --- MongoDB Setup ---
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
        if not project_id:
            channel.basic_ack(delivery_tag=method.delivery_tag)
            return
        
        print(f"\n[+] Starting Analysis for project_id: {project_id}")

        project_doc = db_collection.find_one({"_id": ObjectId(project_id)})
        if not project_doc:
            channel.basic_ack(delivery_tag=method.delivery_tag)
            return

        temp_dir = tempfile.TemporaryDirectory()
        
        pcap_object_name = project_doc.get("pcap_object_name")
        binary_object_name = project_doc.get("binary_object_name")

        local_pcap_path = Path(temp_dir.name) / pcap_object_name
        local_binary_path = Path(temp_dir.name) / binary_object_name

        print(f"[*] Downloading '{pcap_object_name}' from MinIO...")
        minio_client.fget_object(MINIO_BUCKET, pcap_object_name, str(local_pcap_path))

        print(f"[*] Downloading '{binary_object_name}' from MinIO...")
        minio_client.fget_object(MINIO_BUCKET, binary_object_name, str(local_binary_path))

        # make downloaded binary executable
        local_binary_path.chmod(0o755)

        # --- NETWORK ANALYSIS ---
        print("[*] Starting Network Analysis Pipeline...")
        payloads = extract_payloads(str(local_pcap_path))
        clusters = cluster_messages(payloads, n_clusters=10)
        all_aligned_structures = {}
        if clusters:
            for cluster_id, messages in clusters.items():
                if len(messages) < 2: continue
                aligned_structure = align_sequences(messages)
                all_aligned_structures[str(cluster_id)] = {
                    "message_count": len(messages),
                    "inferred_structure": aligned_structure
                }
        network_results = {
            "total_payloads": len(payloads),
            "analyzed_clusters": all_aligned_structures,
            "raw_payloads": payloads
        }
        print("[+] Network analysis complete.")

        # --- BINARY ANALYSIS ---
        print("[*] Starting Binary Analysis Pipeline...")
        target_binary_to_trace = str(local_binary_path)
        trace_log_path = Path(temp_dir.name) / "trace.jsonl"
        frida_script_path = PROJECT_ROOT / 'tools' / 'fridatracer' / 'frida_tracer.py'

        frida_command = [
            sys.executable, 
            str(frida_script_path),
            "--output", 
            str(trace_log_path),
            "--", 
            sys.executable, 
            target_binary_to_trace
        ]

        print(f"[*] Executing Frida tracer: {' '.join(frida_command)}")

        tracer_process = subprocess.Popen(
            frida_command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True            
        )
        ready = False
        start_time = time.time()
        for line in iter(tracer_process.stdout.readline, ''):
            if "---TRACER-READY---" in line:
                print("[+] Tracer is ready. Proceeding with client.")
                ready = True
                break
            if time.time() - start_time > 15: 
                raise Exception("Tracer failed to send ready signal in time.")
        
        if not ready:
            raise Exception("Tracer process exited before sending ready signal.")

        print("[*] Sending client data to trigger the trace...")
        client_script_path = PROJECT_ROOT / 'test_artifacts' / 'echo_client.py'
        subprocess.run([sys.executable, str(client_script_path)], timeout=3, check=True)

        print("[+] Terminating tracer process.")
        tracer_process.terminate()
        try:
            tracer_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            tracer_process.kill()
        print("Tracer process finished.")

        # Parse trace and create bag-of-words
        instruction_mnemonics = []
        if trace_log_path.exists():
            with open(trace_log_path, 'r') as f:
                for line in f:
                    try:
                        trace = json.loads(line)
                        mnemonic = trace.get('mnemonic')
                        if mnemonic:
                            instruction_mnemonics.append(mnemonic)
                    except (json.JSONDecodeError, IndexError):
                        continue
        
        binary_results = {
            "mnemonic_counts": dict(Counter(instruction_mnemonics))
        }
        print(f"[+] Binary analysis complete. Found {len(instruction_mnemonics)} instructions.")
        pprint(binary_results)

        # --- FINAL MODEL & SAVE ---
        final_model = {
            "network_model": network_results,
            "binary_model": binary_results
        }
        
        print(f"[*] Saving inferred protocol model to MongoDB...")
        db_collection.update_one(
            {"_id": ObjectId(project_id)},
            {"$set": {"inferred_protocol_model": final_model, "status": "analysis_complete"}}
        )
        print("[+] Full analysis run finished successfully.")

        channel.basic_ack(delivery_tag=method.delivery_tag)
    
    except Exception as e:
        print(f"[-] A critical error occurred during task processing: {e}", file=sys.stderr)
        if tracer_process and tracer_process.stderr:
            stderr_output = "".join(tracer_process.stderr.readlines())
            if stderr_output:
                print(f"--- Tracer Stderr ---\n{stderr_output}\n--------------------", file=sys.stderr)
        if 'method' in locals() and method:
            channel.basic_ack(delivery_tag=method.delivery_tag)
    finally:
        if temp_dir:
            temp_dir.cleanup()

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
