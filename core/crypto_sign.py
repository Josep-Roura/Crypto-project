# crypto_sign.py

from typing import Tuple
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

def ed25519_generate_keypair() -> Tuple[bytes, bytes]:
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),  # la ciframos nosotros con AES-GCM(user_secret)
    )
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv_pem, pub_pem

def ed25519_sign(priv_pem: bytes, message: bytes) -> bytes:
    key = serialization.load_pem_private_key(priv_pem, password=None)
    return key.sign(message)

def ed25519_verify(pub_pem: bytes, message: bytes, signature: bytes) -> None:
    pub = serialization.load_pem_public_key(pub_pem)
    pub.verify(signature, message)  # lanza InvalidSignature si no es válida
