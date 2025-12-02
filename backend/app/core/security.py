# backend/app/core/security.py

from passlib.context import CryptContext
from passlib.exc import UnknownHashError

# Usamos SOLO pbkdf2_sha256 para evitar problemas con bcrypt
pwd_context = CryptContext(
    schemes=["pbkdf2_sha256"],
    deprecated="auto",
)


def hash_password(password: str) -> str:
    """Calcula el hash de la contraseña con PBKDF2-HMAC-SHA256.

    Algoritmo: `pbkdf2_sha256` gestionado por Passlib, que aplica miles de iteraciones
    y una sal aleatoria interna para cada llamada.
    Entradas: contraseña en texto plano (se limita a 128 chars para evitar abusos).
    Salidas: cadena de hash en formato Passlib lista para almacenar en la base de
    datos sin guardar la contraseña real.
    """
    if len(password) > 128:
        password = password[:128]
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Valida una contraseña frente a su hash PBKDF2.

    Algoritmo: comparación usando `pbkdf2_sha256` de Passlib, que incluye verificación
    constante y manejo de la sal almacenada en el propio hash.
    Entradas: contraseña en claro y hash previamente generado.
    Salidas: `True` si coincide; `False` si el hash es inválido, antiguo o la clave no
    corresponde.
    """
    if len(plain_password) > 128:
        plain_password = plain_password[:128]

    try:
        return pwd_context.verify(plain_password, hashed_password)
    except UnknownHashError:
        # Hash antiguo que ya no sabemos verificar → como si la contraseña fuera mala
        return False
