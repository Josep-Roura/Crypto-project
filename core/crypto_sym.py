import os, hashlib, base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def aesgcm_encrypt(key: bytes, data: bytes, aad: bytes=b""):
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, data, aad)
    return nonce, ct

def aesgcm_decrypt(key: bytes, nonce: bytes, ct: bytes, aad: bytes=b""):
    return AESGCM(key).decrypt(nonce, ct, aad)

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def b64(x: bytes) -> str:
    return base64.b64encode(x).decode()

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode())
