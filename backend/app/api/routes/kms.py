import base64
import time
from datetime import datetime, timedelta

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlmodel import Session, select

from app.models import User, SessionKey
from app.core.db import engine
from app.core.crypto import encrypt_with_rsa

router = APIRouter(tags=["kms"])

class KeyRequest(BaseModel):
    username: str  # 實際上會對應到 User.email
    timestamp: int
    signature_b64: str


@router.post("/kms/request-key")
def request_session_key(data: KeyRequest):
    now = int(time.time())
    if abs(now - data.timestamp) > 60:
        raise HTTPException(status_code=400, detail="Timestamp too old or invalid")

    with Session(engine) as session:
        # 查詢對應使用者
        user = session.exec(select(User).where(User.email == data.username)).first()
        if not user or not user.public_key:
            raise HTTPException(status_code=404, detail="User not found or missing public key")

        # 解析使用者公鑰（PEM 格式字串）
        try:
            public_key = serialization.load_pem_public_key(user.public_key.encode())
        except Exception:
            raise HTTPException(status_code=500, detail="Invalid public key format")

        # 驗證簽章
        message = f"{data.username}:{data.timestamp}".encode()
        signature = base64.b64decode(data.signature_b64)

        try:
            public_key.verify(
                signature,
                message,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
        except Exception:
            raise HTTPException(status_code=403, detail="Signature verification failed")

        # 查詢是否已有未過期的 SessionKey
        existing_key = session.exec(
            select(SessionKey)
            .where(SessionKey.user_id == user.id)
            .where(SessionKey.expires_at > datetime.utcnow())
        ).first()

        if existing_key:
            return {
                "session_key_encrypted": existing_key.session_key_encrypted,
                "expires_in": int((existing_key.expires_at - datetime.utcnow()).total_seconds())
            }

        # 產生新的 AES session key
        session_key = AESGCM.generate_key(bit_length=256)
        expires_at = datetime.utcnow() + timedelta(minutes=10)

        # 使用公鑰加密 session key
        encrypted_key = encrypt_with_rsa(public_key, session_key)
        encrypted_key_b64 = base64.b64encode(encrypted_key).decode()

        # 儲存 SessionKey 到資料庫
        new_key = SessionKey(
            user_id=user.id,
            session_key_encrypted=encrypted_key_b64,
            expires_at=expires_at
        )
        session.add(new_key)
        session.commit()
    
        print(f"New session key generated for user {user.email}: {encrypted_key_b64}")
        return {
            "session_key_encrypted": encrypted_key_b64,
            "expires_in": 600
        }