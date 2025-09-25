import pika
import time
import os
import sys
import json
import subprocess
import tempfile

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

def correlate_results(network_analysis, binary_trace):
    """ For now, this combines the results from both analysis phases into a 
        single structured object, an Intermediate Representation (IR).
        This will be the data model for future, more advanced correlation.
    """
    print("\n[*] Correlating Network and Binary Analysis Results...")

    intermediate_representation = {
        "network_model": network_analysis,
        "binary_model": {
            "memory_traces": binary_trace
        },
        "correlation_status": "placeholder_v1" # versioning model.
    }

    print("[+] Correlation complete. Intermediate Representation created.")
    return intermediate_representation

def process_task(channel, method, properties, body):
    """ This is the callback func for processing a task from the queue.
        This func orchestrates the entire analysis pipeline.
    """
    temp_dir = None
    try:
        message = json.loads(body.decode())
        project_id = message.get("project_id")

        if not project_id:
            print("[-] Message is missing 'project_id'. Discarding.", file=sys.stderr)
            # acknowledge mssg even if its malformed to remove it from queue
            channel.basic_ack(delivery_tag=method.delivery_tag)
            return
        
        print(f"[+] Starting Analysis for project_id: {project_id}")

        # 1. Fetch project data from MongoDB
        print(f"[*] Fetching project details from MongoDB...")
        project_doc = db_collection.find_one({"_id": ObjectId(project_id)})
        if not project_doc:
            print(f"[-] Project ID {project_id} not found in database. Discarding.", file=sys.stderr)
            channel.basic_ack(delivery_tag=method.delivery_tag)
            return

        # 2. Download artifact from MinIO
        minio_object_name = project_doc.get("minio_object_name")
        temp_dir = tempfile.TemporaryDirectory()
        local_artifact_path = Path(temp_dir.name) / minio_object_name

        print(f"[*] Downloading '{minio_object_name}' from MinIO...")
        minio_client.fget_object(MINIO_BUCKET, minio_object_name, str(local_artifact_path))
        print(f"[+] Artifact downloadd to '{local_artifact_path}'")

        # 3. Run Network Analysis Pipeline
        print("[*] Starting Network Analysis Pipeline...")
        payloads = extract_payloads(str(local_artifact_path))
        clusters = cluster_messages(payloads, n_clusters=10)

        all_aligned_structures = {}
        if clusters:
            print(f"[*] Found {len(clusters)} message clusters. Analyzing each...")
            for cluster_id, messages in clusters.items():
                # MSA requires at least 2 messaes to compare.
                if len(messages) < 2:
                    print(f"[*] Skipping Cluster {cluster_id}: not enough messages for alignment ({len(messages)}).")
                    continue
                print(f"[*] Running MAFFT sequence alignment on Cluster {cluster_id} \
                      ({len(messages)} messages)...")
                aligned_structure = align_sequences(messages)
                all_aligned_structures[str(cluster_id)] = {
                    "message_count": len(messages),
                    "inferred_structure": aligned_structure
                }
            
            network_results = {
                "total_payloads": len(payloads),
                "total_clusters_found": len(clusters),
                "analyzed_cluster_count": len(all_aligned_structures),
                "message_templates": all_aligned_structures
            }
            print("[+] Comprehensive network analysis complete.")
            pprint(network_results)
        else:
            print("[-] Network analysis failed or produced no clusters.", file=sys.stderr)
            network_results = {}
        
        print("[*] Starting Binary Analysis Pipeline...")
        target_binary_to_trace = "/bin/ping"
        trace_log_path = Path(temp_dir.name) / "trace.log"
        frida_script_path = PROJECT_ROOT / 'tools' / 'fridatracer' / 'frida_tracer.py'

        frida_command = [
            sys.executable,
            str(frida_script_path),
            "--output",
            str(trace_log_path),
            "--",
            target_binary_to_trace,
            "localhost",
            "-c",
            "1"
        ]

        print(f"[*] Executing Frida tracer: {' '.join(frida_command)}")
        subprocess.run(
            frida_command, 
            capture_output=True, 
            text=True, 
            check=True
        )

        binary_trace_results = []
        if trace_log_path.exists():
            with open(trace_log_path, 'r') as f:
                lines = f.readlines()
                if len(lines) > 1:
                    for line in lines[1:]:
                        parts = line.strip().split(',')
                        if len(parts) == 3:
                            binary_trace_results.append({
                                "buffer_address": parts[0],
                                "bytes_read": int(parts[1]),
                                "handler_functions": parts[2],
                            })
        print(f"[+] Binary analysis complete. Found {len(binary_trace_results)} trace(s).")
        pprint(binary_trace_results)

        # 4. Correlation and saving results.
        final_model = correlate_results(network_results, binary_trace_results)
        print(f"[*] Saving inferred protocol model to MongoDB...")
        db_collection.update_one(
            {"_id": ObjectId(project_id)},
            {
                "$set": {
                    "inferred_protocol_model": final_model,
                    "status": "analysis_complete"
                }
            }
        )
        print("[+] Results saved successfully.")
        print(f"[+] Analysis results generated.")
        print(f"[+] Full Analysis run finished for project_id: {project_id}")

        channel.basic_ack(delivery_tag=method.delivery_tag)
    
    except Exception as e:
        print(f"[-] A critical error occurred during task processing: {e}")
        channel.basic_ack(delivery_tag=method.delivery_tag)
    finally:
        if temp_dir:
            temp_dir.cleanup()

def main():
    """ Main function for the worker.
        Initializes service clients and start the worker.
    """
    global mongo_client, minio_client, db_collection

    print("[*] Correlation service worker starting...")

    print("[*] Connecting to MongoDB...")
    mongo_client = MongoClient(MONGO_URI)
    db = mongo_client[MONGO_DB_NAME]
    db_collection = db["projects"]
    print("[+] MongoDB connected.")

    print("[*] Connecting to MinIO...")
    minio_client = Minio(
        MINIO_ENDPOINT,
        access_key=MINIO_ACCESS_KEY,
        secret_key=MINIO_SECRET_KEY,
        secure=False
    )
    print("[+] MinIO connected.")

    connection = None
    while True:
        try:
            print(f"[*] Connecting to RabbitMQ at '{RABBITMQ_HOST}'...")
            connection = pika.BlockingConnection(
                pika.ConnectionParameters(host=RABBITMQ_HOST)
            )
            channel = connection.channel()
            channel.queue_declare(queue=CORRELATION_QUEUE, durable=True)
            print(f"[*] Waiting for tasks on queue '{CORRELATION_QUEUE}'. To exit, press CTRL+C")
            channel.basic_qos(prefetch_count=1)

            # register 'process_task' func as callback for new mssgs.
            channel.basic_consume(
                queue=CORRELATION_QUEUE,
                on_message_callback=process_task
            )
            channel.start_consuming()
        except pika.exceptions.AMQPConnectionError as e:
            print(f"[-] RabbitMQ connection failed: {e}. Retrying in 5 seconds...")
            time.sleep(5)
        except KeyboardInterrupt:
            print("\n[*] Shutting down worker...")
            if connection and connection.is_open:
                connection.close()
            if mongo_client:
                mongo_client.close()
            break
        except Exception as e:
            print(f"[-] An unexpected error occurred in the main loop: {e}")
            time.sleep(5)


if __name__ == '__main__':
    main()
            
