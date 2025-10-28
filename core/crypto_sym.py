# --------------------------------------------------------------
# File: crypto_sym.py
# Description: Primitivas AES-GCM para cifrado y descifrado simétrico seguro.
# --------------------------------------------------------------
"""Rutinas de cifrado simétrico para proteger datos sensibles."""

import os
from typing import Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from core.models import AesGcmResult


def encrypt_aes_gcm(plaintext: bytes) -> AesGcmResult:
    """Cifra datos con AES-GCM usando una DEK aleatoria de 256 bits.

    Args:
        plaintext (bytes): Datos en claro que se cifrarán.

    Returns:
        AesGcmResult: Resultado con `ciphertext`, `nonce` y `tag`.

    """

    dek = os.urandom(32)
    nonce = os.urandom(12)
    aes = AESGCM(dek)
    ct_full = aes.encrypt(nonce, plaintext, associated_data=None)
    tag = ct_full[-16:]
    ciphertext = ct_full[:-16]
    return AesGcmResult(ciphertext=ciphertext, nonce=nonce, tag=tag)


def aes_gcm_encrypt_with_key(
    key: bytes, plaintext: bytes, aad: Optional[bytes] = None
) -> Tuple[bytes, bytes, bytes]:
    """Cifra datos con AES-GCM utilizando una clave proporcionada.

    Args:
        key (bytes): Clave simétrica de 128, 192 o 256 bits.
        plaintext (bytes): Datos a cifrar.
        aad (Optional[bytes]): Datos autenticados adicionales.

    Returns:
        Tuple[bytes, bytes, bytes]: Ciphertext sin etiqueta, nonce y tag.

    """

    nonce = os.urandom(12)
    aes = AESGCM(key)
    ct_full = aes.encrypt(nonce, plaintext, aad)
    tag = ct_full[-16:]
    ciphertext = ct_full[:-16]
    return ciphertext, nonce, tag


def aes_gcm_decrypt_with_key(
    key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, aad: Optional[bytes] = None
) -> bytes:
    """Descifra datos con AES-GCM utilizando la clave simétrica proporcionada.

    Args:
        key (bytes): Clave simétrica que protege los datos.
        nonce (bytes): Vector de inicialización de 96 bits.
        ciphertext (bytes): Datos cifrados sin etiqueta.
        tag (bytes): Etiqueta de autenticación de 128 bits.
        aad (Optional[bytes]): Datos autenticados adicionales.

    Returns:
        bytes: Mensaje original en claro.

    """

    aes = AESGCM(key)
    return aes.decrypt(nonce, ciphertext + tag, aad)
