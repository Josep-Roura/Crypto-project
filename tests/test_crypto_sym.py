# tests/test_crypto_sym.py
import os
import pytest
from core.crypto_sym import aes_gcm_encrypt_with_key, aes_gcm_decrypt_with_key

def test_aes_gcm_roundtrip_ok():
    key = os.urandom(32)  # 256-bit
    plaintext = os.urandom(128)
    ct, nonce, tag = aes_gcm_encrypt_with_key(key, plaintext)
    recovered = aes_gcm_decrypt_with_key(key, nonce, ct, tag)
    assert recovered == plaintext

def test_aes_gcm_detects_tampering_ciphertext():
    key = os.urandom(32)
    plaintext = b"hola mundo"
    ct, nonce, tag = aes_gcm_encrypt_with_key(key, plaintext)
    # Flip 1 bit del ciphertext
    tampered = bytes([ct[0] ^ 1]) + ct[1:]
    with pytest.raises(Exception):
        aes_gcm_decrypt_with_key(key, nonce, tampered, tag)

def test_aes_gcm_detects_tampering_tag():
    key = os.urandom(32)
    plaintext = b"msg"
    ct, nonce, tag = aes_gcm_encrypt_with_key(key, plaintext)
    # Cambiar tag (flip 1 bit)
    bad_tag = bytes([tag[0] ^ 1]) + tag[1:]
    with pytest.raises(Exception):
        aes_gcm_decrypt_with_key(key, nonce, ct, bad_tag)

def test_aes_gcm_detects_tampering_nonce():
    key = os.urandom(32)
    plaintext = b"msg"
    ct, nonce, tag = aes_gcm_encrypt_with_key(key, plaintext)
    bad_nonce = bytes([nonce[0] ^ 1]) + nonce[1:]
    with pytest.raises(Exception):
        aes_gcm_decrypt_with_key(key, bad_nonce, ct, tag)

def test_aes_gcm_nonce_uniqueness():
    key = os.urandom(32)
    pt = b"x"
    nonces = set()
    # 200 cifrados con nonces aleatorios deben ser únicos (probabilístico)
    for _ in range(200):
        _, nonce, _ = aes_gcm_encrypt_with_key(key, pt)
        assert nonce not in nonces
        nonces.add(nonce)