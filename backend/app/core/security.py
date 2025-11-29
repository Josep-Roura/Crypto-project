# backend/app/core/security.py

from passlib.context import CryptContext
from passlib.exc import UnknownHashError

# Usamos SOLO pbkdf2_sha256 para evitar problemas con bcrypt
pwd_context = CryptContext(
    schemes=["pbkdf2_sha256"],
    deprecated="auto",
)


def hash_password(password: str) -> str:
    """
    Hashea la contraseña en texto plano usando pbkdf2_sha256.
    Truncamos contraseñas absurdamente largas por seguridad / compat.
    """
    if len(password) > 128:
        password = password[:128]
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verifica una contraseña en texto plano contra el hash almacenado.

    Si el hash es de un esquema antiguo (por ejemplo bcrypt) que ya no soportamos,
    Passlib lanza UnknownHashError → lo tratamos como contraseña inválida.
    """
    if len(plain_password) > 128:
        plain_password = plain_password[:128]

    try:
        return pwd_context.verify(plain_password, hashed_password)
    except UnknownHashError:
        # Hash antiguo que ya no sabemos verificar → como si la contraseña fuera mala
        return False
