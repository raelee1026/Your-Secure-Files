from app.core.aes_gcm import AESGCMCipher

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
