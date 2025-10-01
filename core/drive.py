import os, json
from typing import Tuple
from cipherlab.core.crypto_sym import aesgcm_encrypt, aesgcm_decrypt, sha256_hex, b64, b64d
from cipherlab.core.kdf import derive_app_key
from cipherlab.core.config import FILES_DIR

MASTER_KEY = derive_app_key("drive-master-key")  # MVP: una clave derivada del secreto de la app

def encrypt_file_bytes(file_bytes: bytes, filename: str) -> Tuple[dict, bytes]:
    aad = filename.encode()
    nonce, ct = aesgcm_encrypt(MASTER_KEY, file_bytes, aad=aad)
    manifest = {
        "name": filename,
        "hash": sha256_hex(file_bytes),
        "nonce": b64(nonce),
        "aad": b64(aad),
        "size": len(file_bytes)
    }
    return manifest, ct

def decrypt_file_bytes(manifest: dict, ct: bytes) -> bytes:
    nonce = b64d(manifest["nonce"])
    aad = b64d(manifest["aad"])
    return aesgcm_decrypt(MASTER_KEY, nonce, ct, aad=aad)

def save_ciphertext(file_id: int, version: int, ct: bytes) -> str:
    path = os.path.join(FILES_DIR, f"{file_id}_v{version}.bin")
    with open(path, "wb") as f:
        f.write(ct)
    return path

def load_ciphertext(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()
