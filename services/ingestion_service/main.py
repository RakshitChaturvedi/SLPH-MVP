import shutil
import sys
import os
from pathlib import Path
from fastapi import FastAPI, File, UploadFile, HTTPException

from src.scripts.pcap_parser import extract_payloads
from src.scripts.binary_parser import parse_binary

# --- Path setup ---
CURRENT_FILE_PATH = Path(__file__).resolve()
PROJECT_ROOT = CURRENT_FILE_PATH.parent.parent.parent
SRC_PATH = PROJECT_ROOT / "src"
sys.path.insert(0, str(SRC_PATH))

# -- config --
TEMP_UPLOADS_PATH_STR = os.environ.get(
    "TEMP_UPLOADS_DIR",
    str(PROJECT_ROOT / "temp_uploads")
)
TEMP_UPLOADS_DIR = Path(TEMP_UPLOADS_PATH_STR)
TEMP_UPLOADS_DIR.mkdir(exist_ok=True)

app = FastAPI(title="SLPH Ingestion Service")

@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    """ Accepts a file upload, saves it, determines the file type,
        parses it using the appropriate logic, and returns the 
        extracted metadata.
    """

    dest_path = TEMP_UPLOADS_DIR / file.filename

    # 1. Save uploaded file temporarily
    try:
        with open(dest_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
    finally:
        file.file.close()

    # 2. Core parsing logic
    parsed_data = None
    try:
        print(f"[*] Processing file: '{file.filename}'...")

        if file.filename.endswith(('.pcap', '.pcapng')):
            print("[*] Detected PCAP file. Running network trace parses...")
            parsed_data = extract_payloads(str(dest_path))
        else:
            print("[*] Detected non-PCAP file. Running binary parser...")
            parsed_data = parse_binary(str(dest_path))
        
        # 3. binary parser returns empty dict on failure
        if not parsed_data:
            print("[-] Parsing failed. File is not a valid PCAP or supported binary.")
            raise HTTPException(
                status_code=400,
                detail="Unsupported or invalid file format. Could not " \
                "parse as PCAP or Binary."
            )
        
        print("[+] Parrsing successful. Returning metadata.")

        return parsed_data
    
    finally:
        if os.path.exists(dest_path):
            os.remove(dest_path)
            print(f"[*] Cleaned up temporary file: '{dest_path}'")
