import shutil
import sys
import os
import uuid
from pathlib import Path
from fastapi import FastAPI, File, UploadFile, HTTPException
from pymongo import MongoClient
from minio import Minio
from minio.error import S3Error

from src.scripts.pcap_parser import extract_payloads
from src.scripts.binary_parser import parse_binary

# --- Path setup ---
CURRENT_FILE_PATH = Path(__file__).resolve()
PROJECT_ROOT = CURRENT_FILE_PATH.parent.parent.parent
SRC_PATH = PROJECT_ROOT / "src"
sys.path.insert(0, str(SRC_PATH))

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

app = FastAPI(title="SLPH Ingestion Service")

# Establish MongoDB Service Client Connection
try:
    mongo_client = MongoClient(MONGO_URI)
    db = mongo_client[MONGO_DB_NAME]
    projects_collection = db["projects"]
    # test connection
    mongo_client.server_info()
    print("[+] Successfully connected to MongoDB.")
except Exception as e:
    print(f"[-] MongoDB connection failed: {e}", file=sys.stderr)
    mongo_client = None
    projects_collection = None

# Establish MinIO Service Client Connection
try:
    minio_client = Minio(
        MINIO_ENDPOINT,
        access_key=MINIO_ACCESS_KEY,
        secret_key=MINIO_SECRET_KEY,
        secure=False # false for local dev (http)
    )
    # ensure storage bucket exists, if not, create it
    found = minio_client.bucket_exists(MINIO_BUCKET)
    if not found:
        minio_client.make_bucket(MINIO_BUCKET)
        print(f"[*] MinIO bucket '{MINIO_BUCKET}' created.")
    print("[+] Successfully connected to MinIO.")
except Exception as e:
    print(f"[-] MinIO connection failed: {e}", file=sys.stderr)
    minio_client=None

# Upload Route
@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    """ Accepts a file upload
        parses it
        stores the raw file in MinIO
        saves the parsed metadata to MongoDB
    """

    if minio_client is None or projects_collection is None:
        raise HTTPException(
            status_code=503,
            detail="Backend service not available. Check server logs."
        )
    
    # create a unique name for obj in MinIO to avoid name collisions.
    object_name = f"{uuid.uuid4()}-{file.filename}"
    dest_path = TEMP_UPLOADS_DIR / file.filename

    try:
        # 1. Save uploaded file temporarily to disk
        with dest_path.open("wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        
        # 2. Upload original, raw file to MinIO for perma storage
        print(f"[*] Uploading '{file.filename}' to MinIO as '{object_name}'...")
        minio_client.fput_object(
            MINIO_BUCKET, object_name, str(dest_path)
        )
        print("[+] Upload to MinIO successful.")

        # 3. Parse the local temporary file
        print(f"[*] Parsing file: '{file.filename}'...")
        if file.filename.endswith(('.pcap', '.pcapng')):
            parsed_data = extract_payloads(str(dest_path))
            analysis_type = "pcap"
        else:
            parsed_data = parse_binary(str(dest_path))
            analysis_type = "binary"
        
        if not parsed_data:
            raise HTTPException(
                status_code=400,
                detail="Unsupported or invalid file format."
            )

        # 4. Save parsed metadata to MongoDB
        print("[*] Saving metadata to MongoDB...")
        project_document = {
            "project_name": file.filename,
            "minio_object_name": object_name,
            "minio_bucket": MINIO_BUCKET,
            "analysis_type": analysis_type,
            "metadata": parsed_data
        }
        insert_result = projects_collection.insert_one(project_document)
        project_id = str(insert_result.inserted_id)
        print(f"[+] Metadata saved to MongoDB with project ID: {project_id}")

        return {"project_id": project_id, "status": "processed_and_stored"}

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
        if dest_path.exists():
            dest_path.unlink()
            print(f"[*] Cleaned up temporary file: '{dest_path}'")
