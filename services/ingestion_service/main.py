import shutil
import sys
import os
import uuid
import json
from pathlib import Path

from contextlib import asynccontextmanager
from fastapi import FastAPI, File, UploadFile, HTTPException
from pymongo import MongoClient
from minio import Minio
from minio.error import S3Error
import pika

from src.scripts.pcap_parser import extract_payloads
from src.scripts.binary_parser import parse_binary

# --- Path setup ---
CURRENT_FILE_PATH = Path(__file__).resolve()
PROJECT_ROOT = CURRENT_FILE_PATH.parent.parent.parent
SRC_PATH = PROJECT_ROOT / "src"
sys.path.insert(0, str(PROJECT_ROOT))

# --- Config ---
TEMP_UPLOADS_PATH_STR = os.environ.get(
    "TEMP_UPLOADS_DIR",
    str(PROJECT_ROOT / "temp_uploads")
)
TEMP_UPLOADS_DIR = Path(TEMP_UPLOADS_PATH_STR)
TEMP_UPLOADS_DIR.mkdir(exist_ok=True)

# --- MinIO Config ---
MINIO_ENDPOINT = os.environ.get("MINIO_ENDPOINT", "localhost:9000")
MINIO_ACCESS_KEY = os.environ.get("MINIO_ACCESS_KEY", "minioadmin")
MINIO_SECRET_KEY = os.environ.get("MINIO_SECRET_KEY", "minioadmin")
MINIO_BUCKET = "slph-artifacts"

# --- MongoDB Config ---
MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017/")
MONGO_DB_NAME = "slph_projects"

# --- RabbitMQ Config ---
RABBITMQ_HOST = os.environ.get("RABBITMQ_HOST", "localhost")
CORRELATION_QUEUE = "correlation_task_queue"

app_state = {}

# --- Lifespan Event Handler ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    print("[*] Server starting up...")
    
    # Establish MongoDB Service Client Connection
    try:
        mongo_client = MongoClient(MONGO_URI)
        mongo_client.server_info()

        db = mongo_client[MONGO_DB_NAME]
        app_state["projects_collection"] = db["projects"]

        print("[+] Successfully connected to MongoDB.")
    except Exception as e:
        print(f"[-] MongoDB connection failed: {e}", file=sys.stderr)
        app_state["projects_collection"] = None

    # Establish MinIO Service Client Connection
    try:
        minio_client = Minio(
            MINIO_ENDPOINT,
            access_key=MINIO_ACCESS_KEY,
            secret_key=MINIO_SECRET_KEY, 
            secure=False
        )
        found = minio_client.bucket_exists(MINIO_BUCKET)
        if not found: minio_client.make_bucket(MINIO_BUCKET)
        app_state["minio_client"] = minio_client
        print("[+] Successfully connected to MinIO.")
    except Exception as e:
        print(f"[-] MinIO connection failed: {e}", file=sys.stderr)
        app_state["minio_client"] = None
    
    # Establish RabbitMQ Connection
    try:
        connection = pika.BlockingConnection(pika.ConnectionParameters(host=RABBITMQ_HOST))
        channel = connection.channel()
        # durable=true -> queue survives restart
        channel.queue_declare(queue=CORRELATION_QUEUE, durable=True) 
        app_state["rabbitmq_channel"] = channel
        app_state["rabbitmq_connection"] = connection
        print("[+] Successfully connected to RabbitMQ.")
    except Exception as e:
        print(f"[-] RabbitMQ connection failed: {e}", file=sys.stderr)
        app_state["rabbitmq_channel"] = None
        app_state["rabbitmq_connection"] = None
    
    yield

    # --- Shutdown ---
    print("[*] Server shutting down...")
    if app_state.get("rabbitmq_connection") and app_state["rabbitmq_connection"].is_open:
        app_state["rabbitmq_connection"].close()
        print("[*] RabbitMQ connection closed.")
    if mongo_client and mongo_client.is_mongos:
        mongo_client.close()
        print("[*] MongoDB connection closed.")

app = FastAPI(title="SLPH Ingestion Service", lifespan=lifespan)

# Upload Route
@app.post("/upload")
async def upload_artifacts(
    pcap_file: UploadFile = File(..., description="The network traffic capture file (.pcap or .pcapng)"),
    binary_file: UploadFile = File(..., description="The corresponding binary executable that generated the traffic")
):
    """ Accepts a file upload
        parses it
        stores the raw file in MinIO
        saves the parsed metadata to MongoDB
    """

    minio_client = app_state.get("minio_client")
    projects_collection = app_state.get("projects_collection")
    rabbitmq_channel = app_state.get("rabbitmq_channel")

    if minio_client is None or projects_collection is None or rabbitmq_channel is None:
        raise HTTPException(
            status_code=503,
            detail="A backend service is not available."
        )
    
    # create a unique name for obj in MinIO to avoid name collisions.
    pcap_path = TEMP_UPLOADS_DIR / pcap_file.filename
    binary_path = TEMP_UPLOADS_DIR / binary_file.filename

    try:
        # 1. Save uploaded file temporarily to disk
        with pcap_path.open("wb") as buffer:
            shutil.copyfileobj(pcap_file.file, buffer)
        with binary_path.open("wb") as buffer:
            shutil.copyfileobj(binary_file.file, buffer)
        
        # 2. Upload original, raw file to MinIO for perma storage
        pcap_object_name = f"{uuid.uuid4()}-{pcap_file.filename}"
        binary_object_name = f"{uuid.uuid4()}-{binary_file.filename}"

        print(f"[*] Uploading '{pcap_file.filename}' to MinIO as '{pcap_object_name}'...")
        minio_client.fput_object(MINIO_BUCKET, pcap_object_name, str(pcap_path))
        
        print(f"[*] Uploading '{binary_file.filename}' to MinIO as '{binary_object_name}'...")
        minio_client.fput_object(MINIO_BUCKET, binary_object_name, str(binary_path))
        print("[+] Uploads to MinIO successful.")

        # 4. Save parsed metadata to MongoDB
        print("[*] Saving metadata to MongoDB...")
        project_document = {
            "project_name": pcap_file.filename,
            "pcap_object_name": pcap_object_name,
            "binary_object_name": binary_object_name,
            "minio_bucket": MINIO_BUCKET,
            "status": "uploaded"
        }
        insert_result = projects_collection.insert_one(project_document)
        project_id = str(insert_result.inserted_id)
        print(f"[+] Metadata saved to MongoDB with project ID: {project_id}")

        # Publish task message to the queue
        message = {
            "task": "CorrelationTask",
            "project_id": project_id
        }
        rabbitmq_channel.basic_publish(
            exchange='',
            routing_key=CORRELATION_QUEUE,
            body=json.dumps(message),
            properties=pika.BasicProperties(delivery_mode=2)
        )
        print(f"[+] Published CorrelationTask for project ID: {project_id} to RabbitMQ.")

        return {"project_id": project_id, "status": "processing_queued"}

    except S3Error as exc:
        print(f"[-] MinIO Error: {exc}", file=sys.stderr)
        raise HTTPException(
            status_code=500,
            detail="Error during file storage"
        )
    
    except Exception as e:
        print(f"[-] An unexpected error occured: {e}", file=sys.stderr)
        raise HTTPException(
            status_code=500,
            detail="An internal server error occured."
        )

    finally:
        if pcap_path.exists(): pcap_path.unlink()
        if binary_path.exists(): binary_path.unlink()
        print("[*] Cleaned up temporary files.")
