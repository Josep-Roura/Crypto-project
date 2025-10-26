# core/auth.py
# ===== Stdlib =====
import os
import json
import base64
from datetime import datetime, UTC
from typing import Tuple, Dict, Any

# ===== Third-party =====
from argon2 import PasswordHasher, exceptions as argon_exc
from cryptography.exceptions import InvalidTag

# ===== First-party =====
from core.password_policy import check_passphrase_strength
from core.crypto_kdf import derive_kek
from core.crypto_sym import (
    aes_gcm_encrypt_with_key,
    aes_gcm_decrypt_with_key,
)
from core.storage import load_db, save_db


# ===== Config =====
# Estas líneas establecen dónde se va a guardar el json, en concreto users.json
DATA_DIR = os.getenv("STORAGE_PATH", "./_data")
USERS_PATH = os.path.join(DATA_DIR, "users.json")
os.makedirs(DATA_DIR, exist_ok=True)

# Password hasher (Argon2id). m en KiB (64 MiB). Ajusta si tu equipo sufre.
PH = PasswordHasher(time_cost=3, memory_cost=64 * 1024, parallelism=1, hash_len=32)

KDF_PARAMS = {"t": 3, "m": 64 * 1024, "p": 1, "outlen": 32, "alg": "argon2id"}


# ===== Helpers =====
def _b64u(x: bytes) -> str:
    return base64.urlsafe_b64encode(x).decode("ascii").rstrip("=")


def _unb64u(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


# ===== API =====
def register_user(email: str, passphrase: str) -> Tuple[bool, str, str]:
    """
    Crea usuario:
      - Verifica robustez de la passphrase (política de seguridad).
      - Guarda hash Argon2id de la pass (PH.hash).
      - Deriva KEK (Argon2id raw) con salt aleatoria.
      - Genera user_secret (32B) y la cifra con AES-GCM(KEK).
      - Persiste en _data/users.json
    Returns: (ok, msg, debug_log)
    """
    if not email or not passphrase:
        return False, "Email y passphrase son obligatorios.", ""

    # Política de passphrase robusta (server-side)
    ok_pw, reasons, score = check_passphrase_strength(passphrase, email=email)
    if not ok_pw:
        msg = "La passphrase no es suficientemente robusta:\n- " + "\n- ".join(reasons)
        dbg = f"[POLICY] score={score}/100"
        return False, msg, dbg

    db = load_db(USERS_PATH)
    if email in db["users"]:
        return False, "Ya existe un usuario con ese email.", ""

    salt = os.urandom(16)  # 128-bit
    pwd_hash = PH.hash(passphrase)

    # Derivamos KEK
    kek = derive_kek(
        passphrase,
        salt,
        t=KDF_PARAMS["t"],
        m=KDF_PARAMS["m"],
        p=KDF_PARAMS["p"],
        outlen=KDF_PARAMS["outlen"],
    )

    # Generamos y ciframos user_secret
    user_secret = os.urandom(32)  # 256-bit
    ct, nonce, tag = aes_gcm_encrypt_with_key(kek, user_secret)

    db["users"][email] = {
        "salt": _b64u(salt),
        "pwd_hash": pwd_hash,
        "kdf_params": KDF_PARAMS,
        "enc_user_secret": {
            "nonce": _b64u(nonce),
            "tag": _b64u(tag),
            "ct": _b64u(ct),
        },
        "created_at": datetime.now(UTC).isoformat(),
    }
    save_db(db, USERS_PATH)

    debug = (
        f"[REGISTER] Passphrase score={score}/100 (OK)\n"
        f"[REGISTER] Argon2id t={KDF_PARAMS['t']} m={KDF_PARAMS['m']}KiB "
        f"p={KDF_PARAMS['p']} → KEK=256-bit\n"
        f"[REGISTER] AES-GCM-256 nonce=96-bit tag=128-bit user_secret=256-bit"
    )
    return True, "Usuario registrado.", debug


def login(email: str, passphrase: str) -> Tuple[bool, str, Dict[str, Any], str]:
    """
    Verifica pass con Argon2id y devuelve contexto con user_secret descifrada.
    Returns: (ok, msg, ctx, debug_log)
    ctx = {"email":..., "user_secret": bytes}
    """
    db = load_db(USERS_PATH)
    u = db["users"].get(email)
    if not u:
        return False, "Usuario no encontrado.", {}, ""

    try:
        PH.verify(u["pwd_hash"], passphrase)
    except argon_exc.VerifyMismatchError:
        return False, "Passphrase incorrecta.", {}, ""
    except Exception as e:
        return False, f"Error autenticando: {e}", {}, ""

    # Re-derivamos KEK con el mismo salt y params
    salt = _unb64u(u["salt"])
    kp = u["kdf_params"]
    kek = derive_kek(
        passphrase,
        salt,
        t=kp["t"],
        m=kp["m"],
        p=kp["p"],
        outlen=kp["outlen"],
    )

    enc = u["enc_user_secret"]
    nonce = _unb64u(enc["nonce"])
    tag = _unb64u(enc["tag"])
    ct = _unb64u(enc["ct"])

    try:
        user_secret = aes_gcm_decrypt_with_key(kek, nonce, ct, tag)
    except InvalidTag:
        return False, "No se pudo desbloquear la clave del usuario.", {}, ""

    ctx = {"email": email, "user_secret": user_secret}
    debug = (
        f"[LOGIN] Argon2id t={kp['t']} m={kp['m']}KiB p={kp['p']} → KEK=256-bit\n"
        f"[LOGIN] AES-GCM-256 nonce=96-bit tag=128-bit "
        f"user_secret OK ({len(user_secret)*8} bits)"
    )
    return True, "Sesión iniciada.", ctx, debug