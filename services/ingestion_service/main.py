import shutil
import sys
import os
from pathlib import Path
from fastapi import FastAPI, File, UploadFile

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
    """ Accepts a single file upload, saves it to a temporary directory,
        and returns a confirmation message.

        This endpoint is the primary entry point for the entire SLPH
        analysis pipeline

        Args:
            file: The uploaded file, handled by FastAPI as UploadFile object.
        
        Returns:
            A dict containing the name of the uploaded file and its status.
    """

    dest_path = TEMP_UPLOADS_DIR / file.filename

    print(f"[*] Receiving file: '{file.filename}'...")

    try:
        # save uploaded file to destination path.
        # open the destination file in write-binary mode.
        # use shutil.copyfileobj to copy contents 
        # from the upload stream to the file on disk.
        # safer for large files than reading entire file into memory at once.
        with open(dest_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        
        print(f"[+] File '{file.filename}' saved to '{dest_path}'")

        # returns a json success response.
        return {"filename": file.filename, "status": "received"}

    finally:
        # close uploaded file stream to free up resources.
        file.file.close()