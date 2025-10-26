# tests/test_crypto_sign.py
import pytest
from core.crypto_sign import (
    ed25519_generate_keypair,
    ed25519_sign,
    ed25519_verify,
)

def _expect_invalid(check_callable):
    try:
        ok = check_callable()
    except Exception:
        return
    assert ok is False

def _verify_ok(pk, data, sig):
    """
    Considera éxito si:
      - la función no lanza y devuelve None (estilo 'no news = good news'), o
      - la función devuelve True explícitamente.
    """
    try:
        res = ed25519_verify(pk, data, sig)
    except Exception as exc:  # fallo explícito
        raise AssertionError(f"Verificación falló con excepción: {exc}") from exc
    if res is None:
        return True
    return bool(res)

def test_sign_verify_ok():
    sk, pk = ed25519_generate_keypair()
    data = b"mensaje importante"
    sig = ed25519_sign(sk, data)
    assert _verify_ok(pk, data, sig)

def test_verify_fails_with_other_key():
    sk1, pk1 = ed25519_generate_keypair()
    sk2, pk2 = ed25519_generate_keypair()
    data = b"hola"
    sig = ed25519_sign(sk1, data)
    _expect_invalid(lambda: ed25519_verify(pk2, data, sig))

def test_verify_fails_if_message_tampered():
    sk, pk = ed25519_generate_keypair()
    data = b"abc123"
    sig = ed25519_sign(sk, data)
    tampered = b"abc124"
    _expect_invalid(lambda: ed25519_verify(pk, tampered, sig))