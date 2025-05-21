from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


def encrypt_with_rsa(public_key, data: bytes) -> bytes:
    """
    使用 RSA 公鑰加密資料，通常用來加密 AES session key。
    
    :param public_key: 已解析的 RSA 公鑰 (PEM -> public key object)
    :param data: 要加密的 bytes，例如 AES-GCM 的 session key
    :return: 加密後的 bytes
    """
    # return public_key.encrypt(
    #     data,
    #     padding.PKCS1v15() 
    # )
    return public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
