# --------------------------------------------------------------
# File: test_password_policy.py
# Description: Pruebas para la verificación de robustez de passphrases.
# --------------------------------------------------------------

import pytest

from core.password_policy import check_passphrase_strength


def test_policy_accepts_strong_pass():
    """Valida que una passphrase sólida cumpla la política definida.

    Returns:
        None: Las aserciones revisan la puntuación y las recomendaciones.
    """
    ok, reasons, score = check_passphrase_strength(
        "Str0ng_P@ssw0rd!!", email="user@test.com"
    )
    assert ok
    assert score >= 70
    assert not reasons


@pytest.mark.parametrize(
    "pw",
    [
        "short7!",  # menor a 12 caracteres
        "alllowercaseletters",  # solo una clase
        "PASSWORDONLY",  # solo mayúsculas
        "123456789012",  # solo dígitos
        "user1234test",  # contiene fragmentos del email
    ],
)
def test_policy_rejects_weak(pw):
    """Comprueba que distintas passphrases débiles sean rechazadas.

    Args:
        pw (str): Passphrase candidata proporcionada por el parámetro parametrizado.

    Returns:
        None: Las aserciones verifican la presencia de motivos de rechazo.
    """
    ok, reasons, _ = check_passphrase_strength(pw, email="user@test.com")
    assert not ok
    assert reasons


def test_policy_blocks_repetitions_and_spaces():
    """Asegura que las repeticiones y espacios provoquen rechazo.

    Returns:
        None: Las aserciones comprueban los motivos devueltos.
    """
    ok1, reasons1, _ = check_passphrase_strength("AAAaaaa1111!!!!", email=None)
    ok2, reasons2, _ = check_passphrase_strength("ValidBut Has Space1!", email=None)
    assert not ok1 and any("repeticiones" in r.lower() for r in reasons1)
    assert not ok2 and any("espacios" in r.lower() for r in reasons2)
