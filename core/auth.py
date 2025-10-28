# --------------------------------------------------------------
# File: auth.py
# Description: Operaciones de alta y autenticación con gestión segura de secretos.
# --------------------------------------------------------------
"""Funciones de negocio para registrar usuarios y validar credenciales."""

from __future__ import annotations

import base64
import json
import os
from datetime import UTC, datetime
from typing import Any, Dict, Tuple

from argon2 import PasswordHasher, exceptions as argon_exc
from cryptography.exceptions import InvalidTag

from core.crypto_kdf import derive_kek
from core.crypto_sym import aes_gcm_decrypt_with_key, aes_gcm_encrypt_with_key
from core.password_policy import check_passphrase_strength
from core.storage import load_db, save_db

# Directorios de persistencia de datos para la base de usuarios.
DATA_DIR = os.getenv("STORAGE_PATH", "./_data")
USERS_PATH = os.path.join(DATA_DIR, "users.json")
os.makedirs(DATA_DIR, exist_ok=True)

# Configuración común para derivación Argon2id de hashes y KEK.
PH = PasswordHasher(time_cost=3, memory_cost=64 * 1024, parallelism=1, hash_len=32)
KDF_PARAMS = {"t": 3, "m": 64 * 1024, "p": 1, "outlen": 32, "alg": "argon2id"}


def _b64u(data: bytes) -> str:
    """Codifica datos binarios en Base64 URL-safe sin relleno."""

    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _unb64u(value: str) -> bytes:
    """Decodifica datos codificados en Base64 URL-safe gestionando el relleno."""

    pad = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + pad)


def register_user(email: str, passphrase: str) -> Tuple[bool, str, str]:
    """Registra un usuario aplicando controles de seguridad y cifrado.

    Args:
        email (str): Correo electrónico que identifica al usuario.
        passphrase (str): Passphrase propuesta que se validará y protegerá.

    Returns:
        Tuple[bool, str, str]: Indicador de éxito, mensaje de resultado y traza
        de depuración para diagnósticos.

    """
    if not email or not passphrase:
        return False, "Email y passphrase son obligatorios.", ""

    # Valida robustez de la passphrase según política interna.
    ok_pw, reasons, score = check_passphrase_strength(passphrase, email=email)
    if not ok_pw:
        msg = "La passphrase no es suficientemente robusta:\n- " + "\n- ".join(reasons)
        dbg = f"[POLICY] score={score}/100"
        return False, msg, dbg

    db = load_db(USERS_PATH)
    if email in db["users"]:
        return False, "Ya existe un usuario con ese email.", ""

    salt = os.urandom(16)
    pwd_hash = PH.hash(passphrase)

    # Deriva el KEK que protegerá el secreto simétrico del usuario.
    kek = derive_kek(
        passphrase,
        salt,
        t=KDF_PARAMS["t"],
        m=KDF_PARAMS["m"],
        p=KDF_PARAMS["p"],
        outlen=KDF_PARAMS["outlen"],
    )

    # Cifra un nuevo secreto simétrico de 256 bits vinculado al usuario.
    user_secret = os.urandom(32)
    ciphertext, nonce, tag = aes_gcm_encrypt_with_key(kek, user_secret)

    db.setdefault("users", {})[email] = {
        "salt": _b64u(salt),
        "pwd_hash": pwd_hash,
        "kdf_params": KDF_PARAMS,
        "enc_user_secret": {
            "nonce": _b64u(nonce),
            "tag": _b64u(tag),
            "ct": _b64u(ciphertext),
        },
        "created_at": datetime.now(UTC).isoformat(),
    }
    save_db(db, USERS_PATH)

    debug = (
        f"[REGISTER] Score={score}/100 OK\n"
        f"[REGISTER] Argon2id t={KDF_PARAMS['t']} m={KDF_PARAMS['m']}KiB p={KDF_PARAMS['p']}\n"
        f"[REGISTER] AES-GCM-256 nonce=96-bit tag=128-bit user_secret=256-bit"
    )
    return True, "Usuario registrado.", debug


def login(email: str, passphrase: str) -> Tuple[bool, str, Dict[str, Any], str]:
    """Autentica al usuario y recupera el secreto cifrado asociado.

    Args:
        email (str): Correo electrónico con el que el usuario se registró.
        passphrase (str): Passphrase introducida durante el inicio de sesión.

    Returns:
        Tuple[bool, str, Dict[str, Any], str]: Indicador de éxito, mensaje para
        la interfaz, contexto con `user_secret` y traza de depuración.

    """
    db = load_db(USERS_PATH)
    user_record = db.get("users", {}).get(email)
    if not user_record:
        return False, "Usuario no encontrado.", {}, ""

    try:
        PH.verify(user_record["pwd_hash"], passphrase)
    except argon_exc.VerifyMismatchError:
        return False, "Passphrase incorrecta.", {}, ""
    except argon_exc.VerificationError:
        return False, "Error verificando la passphrase.", {}, ""

    salt = _unb64u(user_record["salt"])
    params = user_record["kdf_params"]
    kek = derive_kek(
        passphrase,
        salt,
        t=params["t"],
        m=params["m"],
        p=params["p"],
        outlen=params["outlen"],
    )

    enc = user_record["enc_user_secret"]
    nonce = _unb64u(enc["nonce"])
    tag = _unb64u(enc["tag"])
    ciphertext = _unb64u(enc["ct"])

    try:
        user_secret = aes_gcm_decrypt_with_key(kek, nonce, ciphertext, tag)
    except InvalidTag:
        return False, "No se ha podido descifrar el secreto del usuario.", {}, ""

    context: Dict[str, Any] = {"email": email, "user_secret": user_secret}
    debug = (
        f"[LOGIN] Argon2id t={params['t']} m={params['m']}KiB p={params['p']}\n"
        f"[LOGIN] AES-GCM-256 nonce=96-bit tag=128-bit secreto={len(user_secret)*8} bits"
    )
    return True, "Sesión iniciada.", context, debug
