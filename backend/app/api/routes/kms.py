from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from datetime import datetime, timedelta
import base64, time, os
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa

from core.crypto import encrypt_with_rsa

router = APIRouter()

# 模擬使用者資料庫（最終會改為資料庫查詢）
USER_KEYS = {
    "alice": {
        "public_key_pem": open("alice_pub.pem", "rb").read(),
    }
}

# 模擬 session key 暫存（正式版可用 Redis 或資料庫）
SESSION_KEYS = {}  # username: {"key": b"...", "expires_at": timestamp}

class KeyRequest(BaseModel):
    username: str
    timestamp: int
    signature_b64: str

@router.post("/kms/request-key")
def request_session_key(data: KeyRequest):
    now = int(time.time())
    if abs(now - data.timestamp) > 60:
        raise HTTPException(status_code=400, detail="Timestamp too old or invalid")

    user = USER_KEYS.get(data.username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    public_key = serialization.load_pem_public_key(user["public_key_pem"])
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

    # 若已有尚未過期的 session key，直接回傳
    cached = SESSION_KEYS.get(data.username)
    if cached and cached["expires_at"] > now:
        encrypted = encrypt_with_rsa(public_key, cached["key"])
        return {
            "session_key_encrypted": base64.b64encode(encrypted).decode(),
            "expires_in": cached["expires_at"] - now
        }

    # 產生新的 AES session key
    session_key = AESGCM.generate_key(bit_length=256)
    expires_at = now + 600
    SESSION_KEYS[data.username] = {
        "key": session_key,
        "expires_at": expires_at
    }

    encrypted_key = encrypt_with_rsa(public_key, session_key)
    return {
        "session_key_encrypted": base64.b64encode(encrypted_key).decode(),
        "expires_in": 600
    }
