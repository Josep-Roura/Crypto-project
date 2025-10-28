# --------------------------------------------------------------
# File: test_crypto_sign.py
# Description: Pruebas para las primitivas de firma digital basadas en Ed25519.
# --------------------------------------------------------------

import pytest

from core.crypto_sign import ed25519_generate_keypair, ed25519_sign, ed25519_verify


def _expect_invalid(check_callable):
    """Valida que una verificación falle devolviendo False o lanzando excepción.

    Args:
        check_callable (Callable[[], bool]): Función que ejecuta la verificación.

    Returns:
        None: El helper asume control de aserciones internas.
    """
    try:
        ok = check_callable()
    except Exception:
        return
    assert ok is False


def _verify_ok(public_key: bytes, data: bytes, signature: bytes) -> bool:
    """Ejecuta ed25519_verify normalizando su valor de retorno.

    Args:
        public_key (bytes): Clave pública Ed25519.
        data (bytes): Mensaje firmado.
        signature (bytes): Firma Ed25519 a comprobar.

    Returns:
        bool: True si la verificación fue correcta, False en caso contrario.
    """
    try:
        res = ed25519_verify(public_key, data, signature)
    except Exception as exc:
        raise AssertionError(f"Verificación falló con excepción: {exc}") from exc
    if res is None:
        return True
    return bool(res)


def test_sign_verify_ok():
    """Comprueba que la firma generada sea válida con la clave correspondiente.

    Returns:
        None: Las aserciones usan el helper de verificación positiva.
    """
    sk, pk = ed25519_generate_keypair()
    data = b"mensaje importante"
    sig = ed25519_sign(sk, data)
    assert _verify_ok(pk, data, sig)


def test_verify_fails_with_other_key():
    """Verifica que otra clave pública no valide la firma.

    Returns:
        None: Se usan aserciones indirectas para comprobar el rechazo.
    """
    sk1, pk1 = ed25519_generate_keypair()
    sk2, pk2 = ed25519_generate_keypair()
    data = b"hola"
    sig = ed25519_sign(sk1, data)
    _expect_invalid(lambda: ed25519_verify(pk2, data, sig))


def test_verify_fails_if_message_tampered():
    """Comprueba que alterar el mensaje invalide la firma.

    Returns:
        None: Se espera que la verificación falle.
    """
    sk, pk = ed25519_generate_keypair()
    data = b"abc123"
    sig = ed25519_sign(sk, data)
    tampered = b"abc124"
    _expect_invalid(lambda: ed25519_verify(pk, tampered, sig))
