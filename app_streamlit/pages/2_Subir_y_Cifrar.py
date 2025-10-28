# --------------------------------------------------------------
# File: 2_Subir_y_Cifrar.py
# Description: Gestiona la carga, cifrado y firma de archivos mediante Streamlit.
# --------------------------------------------------------------

import base64
import hashlib
import json
import os

import streamlit as st
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from api.pki import pki_verify_cert
from api.services import ensure_user_sign_keys, sign_manifest, verify_manifest_signature
from core.crypto_sym import aes_gcm_encrypt_with_key


def b64u(data: bytes) -> str:
    """Convierte bytes a base64 url-safe sin relleno.

    Args:
        data (bytes): Bloque binario a codificar.

    Returns:
        str: Representación en base64 url-safe sin caracteres de relleno.
    """
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def secure_name(name: str) -> str:
    """Normaliza el nombre de archivo para evitar caracteres problemáticos.

    Args:
        name (str): Nombre original del archivo proporcionado por el usuario.

    Returns:
        str: Nombre limpio y libre de rutas o caracteres inválidos.
    """
    bad = '<>:"/\\|?*'
    for ch in bad:
        name = name.replace(ch, "_")
    return name.strip().replace("..", "_")


# Presenta el título de la sección dedicada al cifrado.
st.title("⬆️ Subir y cifrar")

# Comprueba que la sesión autenticada esté disponible antes de continuar.
uc = st.session_state.get("user_ctx")
if not uc or "email" not in uc or "user_secret" not in uc:
    st.warning("Inicia sesión primero en la página de **Registro y Login**.")
    st.stop()

# Permite seleccionar el archivo a procesar.
f = st.file_uploader("Selecciona un archivo", type=None)
if f and st.button("Cifrar con AES-GCM"):
    data = f.read()

    # Cifra el archivo con una DEK temporal y muestra la telemetría principal.
    DEK = os.urandom(32)
    ct, nonce, tag = aes_gcm_encrypt_with_key(DEK, data)
    st.success("Archivo cifrado (AES-GCM-256).")
    st.code(
        f"AES-GCM-256 | nonce={len(nonce)*8} bits | tag={len(tag)*8} bits\n"
        f"ct_len={len(ct)} bytes"
    )

    # SECURITY: Envuelve la DEK con el secreto del usuario para almacenarla cifrada.
    email = uc["email"]
    user_secret = uc["user_secret"]
    dek_ct, dek_nonce, dek_tag = aes_gcm_encrypt_with_key(user_secret, DEK)

    # Calcula el hash del archivo y prepara el manifiesto firmado.
    content_hash = "sha256:" + hashlib.sha256(data).hexdigest()
    _priv_pem, _pub_pem = ensure_user_sign_keys(email, user_secret)
    manifest = {
        "filename": f.name,
        "size": len(data),
        "algo": "AES-GCM-256",
        "content_hash": content_hash,
    }
    sig_block = sign_manifest(email, user_secret, manifest)
    ok_sig = verify_manifest_signature(manifest, sig_block["cert_pem"], sig_block["signature"])

    # Muestra el manifiesto, la firma asociada y el estado de la validación.
    st.markdown("### Manifiesto firmado")
    st.json(manifest)
    st.markdown("### Firma generada")
    st.code(sig_block["signature"])
    st.success("✅ Firma verificada correctamente" if ok_sig else "❌ Error al verificar la firma")

    # Persistencia local de blobs cifrados y metadatos.
    data_dir = os.getenv("STORAGE_PATH", "./_data")
    user_dir = os.path.join(data_dir, "storage", email)
    os.makedirs(user_dir, exist_ok=True)
    base = secure_name(f.name)

    # Guarda el archivo cifrado como blob binario nonce|ct|tag.
    enc_path = os.path.join(user_dir, base + ".enc")
    with open(enc_path, "wb") as out:
        out.write(nonce + ct + tag)

    # Serializa los metadatos necesarios para la restauración futura.
    meta = {
        "version": 1,
        "original_filename": f.name,
        "stored_as": base + ".enc",
        "algo": "AES-GCM-256",
        "ciphertext": {
            "nonce": b64u(nonce),
            "tag": b64u(tag),
            "length": len(ct),
        },
        "dek_wrapped": {
            "nonce": b64u(dek_nonce),
            "tag": b64u(dek_tag),
            "ct": b64u(dek_ct),
        },
        "manifest": manifest,
        "signature": sig_block,
    }
    meta_path = os.path.join(user_dir, base + ".meta.json")
    with open(meta_path, "w", encoding="utf-8") as out:
        json.dump(meta, out, indent=2, ensure_ascii=False)

    st.success(f"Guardado en: {enc_path}")
    st.caption(f"Sidecar: {meta_path}")

    # Recupera el certificado X.509 generado para el usuario.
    cert_pem = base64.urlsafe_b64decode(sig_block["cert_pem"] + "=" * (-len(sig_block["cert_pem"]) % 4))
    cert = x509.load_pem_x509_certificate(cert_pem)
    st.markdown("### Certificado (X.509) adjunto")
    st.code(cert.public_bytes(encoding=serialization.Encoding.PEM).decode("utf-8"))

    # Expone la información principal del certificado y valida la cadena con la CA local.
    subject = cert.subject.rfc4514_string()
    issuer = cert.issuer.rfc4514_string()
    nb = cert.not_valid_before
    na = cert.not_valid_after
    fp = cert.fingerprint(hashes.SHA256()).hex()

    st.write("**Subject (CN/email):**", subject)
    st.write("**Issuer (CA):**", issuer)
    st.write("**Validez:**", f"{nb} → {na}")
    st.write("**Fingerprint SHA-256:**", fp)
    st.write(
        "**Validación del certificado (contra CA local):**",
        "✅ OK" if pki_verify_cert(cert_pem) else "❌ FALLA",
    )

    # Visualiza la cadena Usuario → AC subordinada → AC raíz.
    ca_dir = os.path.join(data_dir, "ca")
    try:
        with open(os.path.join(ca_dir, "subca_cert.pem"), "rb") as f_sub:
            sub_cert = x509.load_pem_x509_certificate(f_sub.read())
        with open(os.path.join(ca_dir, "ca_cert.pem"), "rb") as f_root:
            root_cert = x509.load_pem_x509_certificate(f_root.read())

        st.markdown("### Cadena de certificados")
        st.write("**User Issuer:**", cert.issuer.rfc4514_string())
        st.write("**SubCA Subject:**", sub_cert.subject.rfc4514_string())
        st.write("**SubCA Issuer:**", sub_cert.issuer.rfc4514_string())
        st.write("**Root Subject:**", root_cert.subject.rfc4514_string())
        st.info("Comprueba que: **User Issuer = SubCA Subject** y **SubCA Issuer = Root Subject**.")
    except FileNotFoundError:
        st.warning("No se encuentran los certificados de CA/SubCA en _data/ca/. ¿Inicializaste la PKI?")
