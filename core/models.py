# --------------------------------------------------------------
# File: models.py
# Description: Modelos de datos comunes utilizados por la capa criptográfica.
# --------------------------------------------------------------
"""Modelos Pydantic que encapsulan estructuras de intercambio criptográfico."""

from pydantic import BaseModel


class AesGcmResult(BaseModel):
    """Representa el resultado de una operación AES-GCM.

    Attributes:
        ciphertext (bytes): Datos cifrados sin etiqueta.
        nonce (bytes): Vector de inicialización utilizado durante el cifrado.
        tag (bytes): Etiqueta de autenticación generada por AES-GCM.

    """

    ciphertext: bytes
    nonce: bytes
    tag: bytes
