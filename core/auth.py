# auth.py
import os
import json
import base64
import datetime as dt
from typing import Tuple, Dict, Any

from argon2 import PasswordHasher, exceptions as argon_exc
from core.crypto_kdf import derive_kek
from core.crypto_sym import (
    aes_gcm_encrypt_with_key,
    aes_gcm_decrypt_with_key,
)

# ===== Config =====
DATA_DIR = os.getenv("STORAGE_PATH", "./_data")        #Estas líneas establecen donde se va a guardar el json, en concreto users.json
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


def _load_db() -> Dict[str, Any]:
    if not os.path.exists(USERS_PATH):
        return {"users": {}}
    with open(USERS_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def _save_db(db: Dict[str, Any]) -> None:
    tmp = USERS_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(db, f, indent=2)
    os.replace(tmp, USERS_PATH)


# ===== API =====
def register_user(email: str, passphrase: str) -> Tuple[bool, str, str]:
    """
    Crea usuario:
      - Guarda hash Argon2id de la pass (PH.hash).
      - Deriva KEK (Argon2id raw) con salt aleatoria.
      - Genera user_secret (32B) y la cifra con AES-GCM(KEK).
      - Persiste en _data/users.json
    Returns: (ok, msg, debug_log)
    """
    if not email or not passphrase:
        return False, "Email y passphrase son obligatorios.", ""

    db = _load_db()
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
        "created_at": dt.datetime.utcnow().isoformat() + "Z",
    }
    _save_db(db)

    debug = (
        f"[REGISTER] Argon2id t={KDF_PARAMS['t']} m={KDF_PARAMS['m']}KiB p={KDF_PARAMS['p']} → KEK=256-bit\n"
        f"[REGISTER] AES-GCM-256 nonce=96-bit tag=128-bit user_secret=256-bit"
    )
    return True, "Usuario registrado.", debug


def login(email: str, passphrase: str) -> Tuple[bool, str, Dict[str, Any], str]:
    """
    Verifica pass con Argon2id y devuelve contexto con user_secret descifrada.
    Returns: (ok, msg, ctx, debug_log)
    ctx = {"email":..., "user_secret": bytes}
    """
    db = _load_db()
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
        passphrase, salt, t=kp["t"], m=kp["m"], p=kp["p"], outlen=kp["outlen"]
    )

    enc = u["enc_user_secret"]
    nonce = _unb64u(enc["nonce"])
    tag = _unb64u(enc["tag"])
    ct = _unb64u(enc["ct"])

    try:
        user_secret = aes_gcm_decrypt_with_key(kek, nonce, ct, tag)
    except Exception:
        return False, "No se pudo desbloquear la clave del usuario.", {}, ""

    ctx = {"email": email, "user_secret": user_secret}
    debug = (
        f"[LOGIN] Argon2id t={kp['t']} m={kp['m']}KiB p={kp['p']} → KEK=256-bit\n"
        f"[LOGIN] AES-GCM-256 nonce=96-bit tag=128-bit user_secret OK ({len(user_secret)*8} bits)"
    )
    return True, "Sesión iniciada.", ctx, debug


    