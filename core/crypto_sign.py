# --------------------------------------------------------------
# File: crypto_sign.py
# Description: Funciones para gestionar claves y firmas Ed25519.
# --------------------------------------------------------------
"""Abstracciones criptográficas para generación y validación Ed25519."""

from typing import Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


def ed25519_generate_keypair() -> Tuple[bytes, bytes]:
    """Genera un par de claves Ed25519 en formato PEM sin cifrar.

    Returns:
        Tuple[bytes, bytes]: Clave privada y pública en formato PEM.

    """

    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv_pem, pub_pem


def ed25519_sign(priv_pem: bytes, message: bytes) -> bytes:
    """Firma un mensaje con la clave privada Ed25519 proporcionada.

    Args:
        priv_pem (bytes): Clave privada en formato PEM sin cifrar.
        message (bytes): Mensaje que se firmará.

    Returns:
        bytes: Firma Ed25519 resultante.

    """

    key = serialization.load_pem_private_key(priv_pem, password=None)
    return key.sign(message)


def ed25519_verify(pub_pem: bytes, message: bytes, signature: bytes) -> None:
    """Verifica una firma Ed25519 lanzando excepción si no es válida.

    Args:
        pub_pem (bytes): Clave pública en formato PEM.
        message (bytes): Mensaje original firmado.
        signature (bytes): Firma a verificar.

    """

    public_key = serialization.load_pem_public_key(pub_pem)
    public_key.verify(signature, message)
