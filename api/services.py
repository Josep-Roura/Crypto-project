# api/services.py
from api.pki import pki_init_ca, pki_issue_user_cert, pki_verify_cert
import os, json, base64, hashlib
from typing import Dict, Any, Tuple

from core.crypto_sym import aes_gcm_encrypt_with_key, aes_gcm_decrypt_with_key
from core.crypto_sign import ed25519_generate_keypair, ed25519_sign, ed25519_verify

DATA_DIR = os.getenv("STORAGE_PATH", "./_data")
USERS_PATH = os.path.join(DATA_DIR, "users.json")

def _b64u(x: bytes) -> str:
    return base64.urlsafe_b64encode(x).decode("ascii").rstrip("=")

def _unb64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def _load_db() -> Dict[str, Any]:
    if not os.path.exists(USERS_PATH):
        return {"users": {}}
    with open(USERS_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

def _save_db(db: Dict[str, Any]) -> None:
    tmp = USERS_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(db, f, indent=2, ensure_ascii=False)
    os.replace(tmp, USERS_PATH)

# ---------- claves de firma ----------
def ensure_user_sign_keys(email: str, user_secret: bytes) -> Tuple[bytes, bytes]:
    """
    Devuelve (priv_pem_en_memoria, pub_pem). Si no existen, genera y guarda la privada
    cifrada con AES-GCM(user_secret) bajo users.json.
    """
    db = _load_db()
    u = db["users"].get(email)
    if u is None:
        raise RuntimeError("Usuario no encontrado")

    if "sign_pubkey_pem" in u and "enc_sign_privkey" in u:
        enc = u["enc_sign_privkey"]
        priv_pem = aes_gcm_decrypt_with_key(
            user_secret,
            _unb64u(enc["nonce"]),
            _unb64u(enc["ct"]),
            _unb64u(enc["tag"]),
        )
        pub_pem = _unb64u(u["sign_pubkey_pem"])
        return priv_pem, pub_pem

    # Generar y persistir
    priv_pem, pub_pem = ed25519_generate_keypair()
    ct, nonce, tag = aes_gcm_encrypt_with_key(user_secret, priv_pem)
    u["sign_pubkey_pem"] = _b64u(pub_pem)
    u["enc_sign_privkey"] = {"nonce": _b64u(nonce), "tag": _b64u(tag), "ct": _b64u(ct)}
    db["users"][email] = u
    _save_db(db)
    return priv_pem, pub_pem

# ---------- firma de manifiestos ----------
def canonical_json_bytes(d: Dict[str, Any]) -> bytes:
    # JSON determinista (sin espacios, claves ordenadas)
    return json.dumps(d, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode("utf-8")

def manifest_digest(manifest: Dict[str, Any]) -> bytes:
    return hashlib.sha256(canonical_json_bytes(manifest)).digest()



def sign_manifest(email: str, user_secret: bytes, manifest: Dict[str, Any]) -> Dict[str, Any]:
    priv_pem, pub_pem = ensure_user_sign_keys(email, user_secret)
    digest = manifest_digest(manifest)
    sig = ed25519_sign(priv_pem, digest)

    # adjuntar el certificado del usuario en lugar de la pubkey suelta
    db = _load_db()
    cert_b64 = db["users"][email]["sign_cert_pem"]
    return {"alg": "Ed25519-SHA256", "cert_pem": cert_b64, "signature": _b64u(sig)}

def verify_manifest_signature(manifest: Dict[str, Any], cert_pem_b64u: str, signature_b64u: str) -> bool:
    cert_pem = _unb64u(cert_pem_b64u)

    # 1) validar certificado contra CA
    if not pki_verify_cert(cert_pem):
        return False

    # 2) extraer pubkey del cert y verificar firma
    from api.pki import pki_pub_from_cert
    pub_pem = pki_pub_from_cert(cert_pem)

    digest = manifest_digest(manifest)
    try:
        ed25519_verify(pub_pem, digest, _unb64u(signature_b64u))
        return True
    except Exception:
        return False
    




def ensure_user_sign_keys(email: str, user_secret: bytes) -> Tuple[bytes, bytes]:
    db = _load_db()
    u = db["users"].get(email)
    if u is None:
        raise RuntimeError("Usuario no encontrado")

    # Si ya existen claves (y cert), descifra privada y devuelve.
    if "sign_pubkey_pem" in u and "enc_sign_privkey" in u:
        enc = u["enc_sign_privkey"]
        priv_pem = aes_gcm_decrypt_with_key(
            user_secret,
            _unb64u(enc["nonce"]),
            _unb64u(enc["ct"]),
            _unb64u(enc["tag"]),
        )
        pub_pem = _unb64u(u["sign_pubkey_pem"])

        # si no tiene cert, emitirlo ahora
        if "sign_cert_pem" not in u:
            pki_init_ca()
            cert_pem = pki_issue_user_cert(email, pub_pem)
            u["sign_cert_pem"] = _b64u(cert_pem)
            db["users"][email] = u
            _save_db(db)

        return priv_pem, pub_pem

    # Generar claves nuevas
    priv_pem, pub_pem = ed25519_generate_keypair()
    ct, nonce, tag = aes_gcm_encrypt_with_key(user_secret, priv_pem)
    u["sign_pubkey_pem"] = _b64u(pub_pem)
    u["enc_sign_privkey"] = {"nonce": _b64u(nonce), "tag": _b64u(tag), "ct": _b64u(ct)}

    # Emitir certificado X.509 (CA local)
    pki_init_ca()
    cert_pem = pki_issue_user_cert(email, pub_pem)
    u["sign_cert_pem"] = _b64u(cert_pem)

    db["users"][email] = u
    _save_db(db)
    return priv_pem, pub_pem