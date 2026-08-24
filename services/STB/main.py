from fastapi import FastAPI, HTTPException
import binascii
import base64
from pydantic import BaseModel
from crypto_service import upload_photo, download_photo
from database.init_db import init_db
import uvicorn


init_db()

app = FastAPI()


class UploadRequest(BaseModel):
    photo_base64: str


@app.post("/upload")
def upload(request: UploadRequest):

    try:
        base64.b64decode(request.photo_base64, validate=True)
    except (ValueError, binascii.Error):
        raise HTTPException(
            status_code=400,
            detail="Invalid Base64 format"
        )

    photo_id, crypto_time_ms, upload_time_ms = upload_photo(request.photo_base64)

    return {
        "photo_id": photo_id,
        "crypto_time_ms": crypto_time_ms,
        "upload_time_ms": upload_time_ms
    }


@app.get("/download/{photo_id}")
def download(photo_id: str):

    photo_base64, download_time_ms, decrypt_time_ms = download_photo(photo_id)

    return {
        "photo": photo_base64,
        "decrypt_time_ms": decrypt_time_ms,
        "download_time_ms": download_time_ms
    }