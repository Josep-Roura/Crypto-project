# --------------------------------------------------------------
# File: services.py
# Description: Servicios de gestión de identidades y firmas digitales para la API.
# --------------------------------------------------------------
"""Funciones de la capa de servicios para emisión y validación de manifiestos."""

import base64
import hashlib
import json
import os
from typing import Any, Dict, Tuple

from api.pki import pki_init_ca, pki_issue_user_cert, pki_verify_cert
from core.crypto_sign import ed25519_generate_keypair, ed25519_sign, ed25519_verify
from core.crypto_sym import aes_gcm_decrypt_with_key, aes_gcm_encrypt_with_key

# Configuración de rutas de persistencia.
DATA_DIR = os.getenv("STORAGE_PATH", "./_data")
USERS_PATH = os.path.join(DATA_DIR, "users.json")


def _b64u(data: bytes) -> str:
    """Convierte datos binarios en una cadena Base64 URL-safe sin relleno.

    Args:
        data (bytes): Datos binarios a convertir.

    Returns:
        str: Representación codificada sin caracteres de relleno.
    """

    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _unb64u(value: str) -> bytes:
    """Decodifica una cadena Base64 URL-safe sin relleno.

    Args:
        value (str): Cadena codificada sin relleno.

    Returns:
        bytes: Datos originales en formato binario.
    """

    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _load_db() -> Dict[str, Any]:
    """Carga la base de datos JSON de usuarios.

    Returns:
        Dict[str, Any]: Contenido del archivo de usuarios o la estructura vacía.
    """

    if not os.path.exists(USERS_PATH):
        return {"users": {}}
    with open(USERS_PATH, "r", encoding="utf-8") as handler:
        return json.load(handler)


def _save_db(db: Dict[str, Any]) -> None:
    """Guarda la base de datos JSON de usuarios de forma atómica.

    Args:
        db (Dict[str, Any]): Datos actualizados que deben persistir.
    """

    tmp_path = USERS_PATH + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as handler:
        json.dump(db, handler, indent=2, ensure_ascii=False)
    os.replace(tmp_path, USERS_PATH)


# SECURITY: la clave privada siempre se almacena cifrada con el secreto del usuario.
def ensure_user_sign_keys(email: str, user_secret: bytes) -> Tuple[bytes, bytes]:
    """Garantiza que el usuario disponga de claves Ed25519 y devuelve la pareja PEM.

    Args:
        email (str): Identificador del usuario propietario de la clave.
        user_secret (bytes): Secreto derivado de las credenciales del usuario.

    Returns:
        Tuple[bytes, bytes]: Par (clave_privada_pem, clave_publica_pem).

    Raises:
        RuntimeError: Si no existe el usuario dentro de la base de datos.
    """

    database = _load_db()
    user = database["users"].get(email)
    if user is None:
        raise RuntimeError("Usuario no encontrado")

    if "sign_pubkey_pem" in user and "enc_sign_privkey" in user:
        encrypted = user["enc_sign_privkey"]
        private_pem = aes_gcm_decrypt_with_key(
            user_secret,
            _unb64u(encrypted["nonce"]),
            _unb64u(encrypted["ct"]),
            _unb64u(encrypted["tag"]),
        )
        public_pem = _unb64u(user["sign_pubkey_pem"])

        # Asegura que el certificado esté emitido para la clave existente.
        if "sign_cert_pem" not in user:
            pki_init_ca()
            certificate_pem = pki_issue_user_cert(email, public_pem)
            user["sign_cert_pem"] = _b64u(certificate_pem)
            database["users"][email] = user
            _save_db(database)

        return private_pem, public_pem

    private_pem, public_pem = ed25519_generate_keypair()
    ciphertext, nonce, tag = aes_gcm_encrypt_with_key(user_secret, private_pem)
    user["sign_pubkey_pem"] = _b64u(public_pem)
    user["enc_sign_privkey"] = {
        "nonce": _b64u(nonce),
        "tag": _b64u(tag),
        "ct": _b64u(ciphertext),
    }

    # Emite y registra el certificado X.509 respaldado por la CA local.
    pki_init_ca()
    certificate_pem = pki_issue_user_cert(email, public_pem)
    user["sign_cert_pem"] = _b64u(certificate_pem)

    database["users"][email] = user
    _save_db(database)
    return private_pem, public_pem


def canonical_json_bytes(payload: Dict[str, Any]) -> bytes:
    """Serializa un diccionario JSON de manera determinista para firmarlo.

    Args:
        payload (Dict[str, Any]): Datos que formarán parte del manifiesto.

    Returns:
        bytes: Representación JSON canonizada en UTF-8.
    """

    # Genera JSON con claves ordenadas y sin espacios para lograr un digest estable.
    return json.dumps(payload, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode("utf-8")


def manifest_digest(manifest: Dict[str, Any]) -> bytes:
    """Calcula el hash SHA-256 del manifiesto canonizado.

    Args:
        manifest (Dict[str, Any]): Manifiesto sobre el cual se generará la huella.

    Returns:
        bytes: Digest resultante de aplicar SHA-256.
    """

    return hashlib.sha256(canonical_json_bytes(manifest)).digest()


def sign_manifest(email: str, user_secret: bytes, manifest: Dict[str, Any]) -> Dict[str, Any]:
    """Firma un manifiesto JSON con las claves del usuario.

    Args:
        email (str): Identificador del usuario firmante.
        user_secret (bytes): Secreto utilizado para descifrar la clave privada.
        manifest (Dict[str, Any]): Contenido estructurado que se firmará.

    Returns:
        Dict[str, Any]: Metadatos de la firma, incluyendo certificado y firma codificada.
    """

    private_pem, _ = ensure_user_sign_keys(email, user_secret)
    digest = manifest_digest(manifest)
    signature = ed25519_sign(private_pem, digest)

    # Recupera el certificado asociado para acompañar la firma.
    database = _load_db()
    certificate_b64 = database["users"][email]["sign_cert_pem"]
    return {
        "alg": "Ed25519-SHA256",
        "cert_pem": certificate_b64,
        "signature": _b64u(signature),
    }


def verify_manifest_signature(manifest: Dict[str, Any], cert_pem_b64u: str, signature_b64u: str) -> bool:
    """Valida una firma de manifiesto con el certificado del firmante.

    Args:
        manifest (Dict[str, Any]): Manifiesto original firmado.
        cert_pem_b64u (str): Certificado del usuario codificado en Base64 URL-safe.
        signature_b64u (str): Firma codificada en Base64 URL-safe.

    Returns:
        bool: ``True`` si la firma es válida; ``False`` en caso contrario.
    """

    certificate_pem = _unb64u(cert_pem_b64u)

    # Primero valida la cadena del certificado frente a la CA.
    if not pki_verify_cert(certificate_pem):
        return False

    from api.pki import pki_pub_from_cert

    public_pem = pki_pub_from_cert(certificate_pem)
    digest = manifest_digest(manifest)
    try:
        ed25519_verify(public_pem, digest, _unb64u(signature_b64u))
        return True
    except Exception:
        return False
