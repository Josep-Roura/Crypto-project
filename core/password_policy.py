# --------------------------------------------------------------
# File: password_policy.py
# Description: Reglas de validación de passphrases para cuentas de usuario.
# --------------------------------------------------------------
"""Utilidades para evaluar la robustez de passphrases en CryptoDrive."""

from __future__ import annotations

import re
from typing import List, Tuple

COMMON = {
    "123456",
    "123456789",
    "12345678",
    "qwerty",
    "password",
    "111111",
    "123123",
    "000000",
    "abc123",
    "letmein",
    "iloveyou",
    "admin",
    "welcome",
    "monkey",
    "dragon",
    "football",
    "baseball",
    "princess",
    "qwertyuiop",
    "passw0rd",
}

LOWER = re.compile(r"[a-z]")
UPPER = re.compile(r"[A-Z]")
DIGIT = re.compile(r"\d")
SYMBOL = re.compile(r"[^\w\s]")


def contains_user_info(passphrase: str, email: str | None) -> bool:
    """Comprueba si la passphrase reutiliza partes del identificador del usuario."""

    if not email:
        return False
    local_part = email.split("@")[0].lower()
    tokens = [local_part, *re.split(r"[._+-]", local_part)]
    tokens = [token for token in tokens if len(token) >= 4]
    passphrase_lower = passphrase.lower()
    return any(token in passphrase_lower for token in tokens)


def class_count(passphrase: str) -> int:
    """Cuenta los grupos de caracteres presentes en la passphrase."""

    return sum(
        [
            1 if LOWER.search(passphrase) else 0,
            1 if UPPER.search(passphrase) else 0,
            1 if DIGIT.search(passphrase) else 0,
            1 if SYMBOL.search(passphrase) else 0,
        ]
    )


def has_long_repetition(passphrase: str, max_run: int = 3) -> bool:
    """Detecta repeticiones largas de un mismo carácter dentro de la passphrase."""

    pattern = rf"(.)\1{{{max_run},}}"
    return re.search(pattern, passphrase) is not None


def check_passphrase_strength(
    passphrase: str, *, email: str | None = None
) -> Tuple[bool, List[str], int]:
    """Evalúa la passphrase y devuelve cumplimiento, motivos y puntuación.

    Args:
        passphrase (str): Passphrase propuesta por el usuario.
        email (str | None): Email para evitar reutilizar identificadores.

    Returns:
        Tuple[bool, List[str], int]: Resultado de validación, motivos de rechazo y
        puntuación acumulada entre 0 y 100.

    """

    reasons: List[str] = []
    score = 0

    length = len(passphrase)
    if length < 12:
        reasons.append("Longitud mínima 12.")
    else:
        score += min(40, (length - 11) * 4)

    classes = class_count(passphrase)
    if classes < 3:
        reasons.append("Usa al menos 3 de: minúsculas, mayúsculas, dígitos, símbolos.")
    else:
        score += 30

    if any(char.isspace() for char in passphrase):
        reasons.append("No se permiten espacios en blanco.")
    else:
        score += 5

    if passphrase.lower() in COMMON:
        reasons.append("Contraseña demasiado común.")
    else:
        score += 10

    if contains_user_info(passphrase, email):
        reasons.append("No incluyas partes de tu email/usuario.")
    else:
        score += 10

    if has_long_repetition(passphrase):
        reasons.append("Evita repeticiones largas del mismo carácter.")
    else:
        score += 5

    score = max(0, min(100, score))
    ok = (
        length >= 12
        and classes >= 3
        and passphrase.lower() not in COMMON
        and not contains_user_info(passphrase, email)
        and not has_long_repetition(passphrase)
        and not any(char.isspace() for char in passphrase)
    )
    return ok, reasons, score
