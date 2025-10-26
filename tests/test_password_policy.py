# tests/test_password_policy.py
import pytest
from core.password_policy import check_passphrase_strength

def test_policy_accepts_strong_pass():
    ok, reasons, score = check_passphrase_strength(
        "Str0ng_P@ssw0rd!!", email="user@test.com"
    )
    assert ok
    assert score >= 70
    assert not reasons  # no debería sugerir mejoras en una pass fuerte

@pytest.mark.parametrize("pw", [
    "short7!",                # <12 chars
    "alllowercaseletters",    # solo una clase
    "PASSWORDONLY",           # solo mayúsculas
    "123456789012",           # solo dígitos (y muy común)
    "user1234test",           # contiene partes del email
])
def test_policy_rejects_weak(pw):
    ok, reasons, _ = check_passphrase_strength(pw, email="user@test.com")
    assert not ok
    assert reasons  # explica el motivo de rechazo

def test_policy_blocks_repetitions_and_spaces():
    ok1, reasons1, _ = check_passphrase_strength("AAAaaaa1111!!!!", email=None)
    ok2, reasons2, _ = check_passphrase_strength("ValidBut Has Space1!", email=None)
    assert not ok1 and any("repeticiones" in r.lower() for r in reasons1)
    assert not ok2 and any("espacios" in r.lower() for r in reasons2)