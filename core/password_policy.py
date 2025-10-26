# core/password_policy.py
import re

COMMON = {
    "123456", "123456789", "12345678", "qwerty", "password", "111111", "123123",
    "000000", "abc123", "letmein", "iloveyou", "admin", "welcome", "monkey",
    "dragon", "football", "baseball", "princess", "qwertyuiop", "passw0rd"
}

LOWER = re.compile(r"[a-z]")
UPPER = re.compile(r"[A-Z]")
DIGIT = re.compile(r"\d")
SYMB  = re.compile(r"[^\w\s]")  # símbolos (no letra/dígito/espacio)

def contains_user_info(pw: str, email: str | None) -> bool:
    if not email:
        return False
    local = email.split("@")[0].lower()
    pw_l = pw.lower()
    # Evita trozos significativos del local-part
    parts = re.split(r"[._+-]", local)
    tokens = [t for t in [local, *parts] if len(t) >= 4]
    return any(t in pw_l for t in tokens)

def class_count(pw: str) -> int:
    return sum([
        1 if LOWER.search(pw) else 0,
        1 if UPPER.search(pw) else 0,
        1 if DIGIT.search(pw) else 0,
        1 if SYMB.search(pw) else 0,
    ])

def has_long_repetition(pw: str, max_run: int = 3) -> bool:
    # Detecta "aaaa", "1111", etc.
    return re.search(r"(.)\1{" + str(max_run) + r",}", pw) is not None

def check_passphrase_strength(pw: str, *, email: str | None = None) -> tuple[bool, list[str], int]:
    """
    Devuelve (ok, motivos, score_0_100)
    """
    reasons = []
    score = 0

    if len(pw) < 12:
        reasons.append("Longitud mínima 12.")
    else:
        score += min(40, (len(pw) - 11) * 4)  # 12→4, 14→12, etc., cap 40

    classes = class_count(pw)
    if classes < 3:
        reasons.append("Usa al menos 3 de: minúsculas, mayúsculas, dígitos, símbolos.")
    else:
        score += 30

    if any(c.isspace() for c in pw):
        reasons.append("No se permiten espacios en blanco.")
    else:
        score += 5

    if pw.lower() in COMMON:
        reasons.append("Contraseña demasiado común.")
    else:
        score += 10

    if contains_user_info(pw, email):
        reasons.append("No incluyas partes de tu email/usuario.")
    else:
        score += 10

    if has_long_repetition(pw):
        reasons.append("Evita repeticiones largas del mismo carácter.")
    else:
        score += 5

    score = max(0, min(100, score))
    ok = (len(pw) >= 12) and (classes >= 3) and (pw.lower() not in COMMON) and \
         (not contains_user_info(pw, email)) and (not has_long_repetition(pw)) and \
         (not any(c.isspace() for c in pw))
    return ok, reasons, score