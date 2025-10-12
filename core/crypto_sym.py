import os
from typing import Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from core.models import AesGcmResult


def encrypt_aes_gcm(plaintext: bytes) -> AesGcmResult:
    """
    Cifra con una DEK aleatoria (32B) y devuelve struct (ciphertext, nonce, tag).
    Útil para pruebas de UI. Para producción, usa las funciones con clave explícita.
    """
    dek = os.urandom(32)   # 256-bit
    nonce = os.urandom(12) # 96-bit
    aes = AESGCM(dek)
    ct_full = aes.encrypt(nonce, plaintext, associated_data=None)
    tag = ct_full[-16:]            # 128-bit
    ciphertext = ct_full[:-16]
    return AesGcmResult(ciphertext=ciphertext, nonce=nonce, tag=tag)


def aes_gcm_encrypt_with_key(
    key: bytes, plaintext: bytes, aad: Optional[bytes] = None
) -> Tuple[bytes, bytes, bytes]:
    """
    Cifra con AES-GCM y clave proporcionada.
    Devuelve (ciphertext_sin_tag, nonce, tag).
    """
    nonce = os.urandom(12)  # 96-bit
    aes = AESGCM(key)
    ct_full = aes.encrypt(nonce, plaintext, aad)
    tag = ct_full[-16:]     # 128-bit
    ciphertext = ct_full[:-16]
    return ciphertext, nonce, tag


def aes_gcm_decrypt_with_key(
    key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, aad: Optional[bytes] = None
) -> bytes:
    """
    Descifra con AES-GCM y clave proporcionada.
    """
    aes = AESGCM(key)
    return aes.decrypt(nonce, ciphertext + tag, aad)
