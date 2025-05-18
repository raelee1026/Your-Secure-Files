from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

class AESGCMCipher:
    def __init__(self, key: bytes):
        if len(key) not in (16, 24, 32):
            raise ValueError("Key must be 128, 192, or 256 bits (16, 24, or 32 bytes) long")
        self.key = key
        self.aesgcm = AESGCM(key)

    def encrypt(self, plaintext: bytes, associated_data: bytes | None = None) -> bytes:
        nonce = os.urandom(12)
        ciphertext = self.aesgcm.encrypt(nonce, plaintext, associated_data)
        return nonce + ciphertext

    def decrypt(self, data: bytes, associated_data: bytes | None = None) -> bytes:
        nonce = data[:12]
        ciphertext = data[12:]
        plaintext = self.aesgcm.decrypt(nonce, ciphertext, associated_data)
        return plaintext

def test_encrypt_decrypt():
    key = b"thisis16byteskey"  # 16 bytes AES-128 key
    cipher = AESGCMCipher(key)

    plaintext = b"Hello, AES-GCM encryption!"
    associated_data = b"associated data"

    encrypted = cipher.encrypt(plaintext, associated_data)
    print("Encrypted (hex):", encrypted.hex())

    decrypted = cipher.decrypt(encrypted, associated_data)
    print("Decrypted:", decrypted)

    assert decrypted == plaintext
    print("Test passed!")

if __name__ == "__main__":
    test_encrypt_decrypt() 