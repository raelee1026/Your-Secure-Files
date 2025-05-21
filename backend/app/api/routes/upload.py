from fastapi import APIRouter, UploadFile, File, Form, Depends, HTTPException
from app.models import EncryptedFile, User
from app.core.auth import get_current_user
from sqlmodel import Session
from app.core.db import engine
from datetime import datetime
import base64
import uuid

router = APIRouter()

@router.post("/upload")
async def upload_encrypted_file(
    file: UploadFile = File(...),
    iv: str = Form(...),
    tag: str = Form(...),
    current_user: User = Depends(get_current_user)
):
    encrypted_bytes = await file.read()

    encrypted_file = EncryptedFile(
        owner_id=current_user.id,
        file_name=file.filename,
        file_content_encrypted=encrypted_bytes,
        iv=base64.b64decode(iv),
        tag=base64.b64decode(tag),
        created_at=datetime.utcnow()
    )

    with Session(engine) as session:
        session.add(encrypted_file)
        session.commit()

    return {"msg": "File uploaded successfully"}
