# --------------------------------------------------------------
# File: test_crypto_sym.py
# Description: Pruebas del cifrado y descifrado simétrico con AES-GCM.
# --------------------------------------------------------------

import os

import pytest

from core.crypto_sym import aes_gcm_decrypt_with_key, aes_gcm_encrypt_with_key


def test_aes_gcm_roundtrip_ok():
    """Comprueba que un cifrado con AES-GCM pueda revertirse correctamente.

    Returns:
        None: Las aserciones evalúan la igualdad entre claro y descifrado.
    """
    key = os.urandom(32)
    plaintext = os.urandom(128)
    ct, nonce, tag = aes_gcm_encrypt_with_key(key, plaintext)
    recovered = aes_gcm_decrypt_with_key(key, nonce, ct, tag)
    assert recovered == plaintext


def test_aes_gcm_detects_tampering_ciphertext():
    """Verifica que cualquier alteración del ciphertext sea detectada.

    Returns:
        None: La expectativa es una excepción al descifrar.
    """
    key = os.urandom(32)
    plaintext = b"hola mundo"
    ct, nonce, tag = aes_gcm_encrypt_with_key(key, plaintext)
    tampered = bytes([ct[0] ^ 1]) + ct[1:]
    with pytest.raises(Exception):
        aes_gcm_decrypt_with_key(key, nonce, tampered, tag)


def test_aes_gcm_detects_tampering_tag():
    """Garantiza que un tag modificado invalide el descifrado.

    Returns:
        None: Se espera una excepción durante la verificación.
    """
    key = os.urandom(32)
    plaintext = b"msg"
    ct, nonce, tag = aes_gcm_encrypt_with_key(key, plaintext)
    bad_tag = bytes([tag[0] ^ 1]) + tag[1:]
    with pytest.raises(Exception):
        aes_gcm_decrypt_with_key(key, nonce, ct, bad_tag)


def test_aes_gcm_detects_tampering_nonce():
    """Comprueba que modificar el nonce provoque fallo en la autenticación.

    Returns:
        None: Se espera una excepción durante el descifrado.
    """
    key = os.urandom(32)
    plaintext = b"msg"
    ct, nonce, tag = aes_gcm_encrypt_with_key(key, plaintext)
    bad_nonce = bytes([nonce[0] ^ 1]) + nonce[1:]
    with pytest.raises(Exception):
        aes_gcm_decrypt_with_key(key, bad_nonce, ct, tag)


def test_aes_gcm_nonce_uniqueness():
    """Evalúa que los nonces aleatorios generados no se repitan.

    Returns:
        None: Las aserciones verifican la unicidad dentro del muestreo.
    """
    key = os.urandom(32)
    pt = b"x"
    nonces = set()
    for _ in range(200):
        _, nonce, _ = aes_gcm_encrypt_with_key(key, pt)
        assert nonce not in nonces
        nonces.add(nonce)
