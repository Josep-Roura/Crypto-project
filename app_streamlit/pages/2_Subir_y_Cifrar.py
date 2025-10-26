import os
import json
import base64
import hashlib
import streamlit as st

from api.services import ensure_user_sign_keys, sign_manifest, verify_manifest_signature
from api.pki import pki_verify_cert
from core.crypto_sym import aes_gcm_encrypt_with_key  # usamos AES-GCM con clave explícita

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization


st.title("⬆️ Subir y cifrar")

# ----------------- helpers locales -----------------
def b64u(x: bytes) -> str:
    return base64.urlsafe_b64encode(x).decode("ascii").rstrip("=")

def secure_name(name: str) -> str:
    bad = '<>:"/\\|?*'
    for ch in bad:
        name = name.replace(ch, "_")
    return name.strip().replace("..", "_")
# ---------------------------------------------------

# Comprobación de sesión
uc = st.session_state.get("user_ctx")
if not uc or "email" not in uc or "user_secret" not in uc:
    st.warning("Inicia sesión primero en la página de **Registro y Login**.")
    st.stop()

f = st.file_uploader("Selecciona un archivo", type=None)
if f and st.button("Cifrar con AES-GCM"):
    data = f.read()

    # ==========================
    # 🔐 CIFRADO REAL EN LOCAL
    # ==========================
    # 1) Generar DEK aleatoria y cifrar el archivo con esa DEK
    DEK = os.urandom(32)  # 256-bit
    ct, nonce, tag = aes_gcm_encrypt_with_key(DEK, data)
    st.success("Archivo cifrado (AES-GCM-256).")
    st.code(
        f"AES-GCM-256 | nonce={len(nonce)*8} bits | tag={len(tag)*8} bits\n"
        f"ct_len={len(ct)} bytes"
    )

    # 2) Envolver la DEK con user_secret (para poder recuperarla tras login)
    email = uc["email"]
    user_secret = uc["user_secret"]
    dek_ct, dek_nonce, dek_tag = aes_gcm_encrypt_with_key(user_secret, DEK)

    # ==========================
    # 🔒 FIRMA DIGITAL (PUNTO 4)
    # ==========================
    # Calcular hash del archivo (manifiesto)
    content_hash = "sha256:" + hashlib.sha256(data).hexdigest()

    # 1) Generar o recuperar las claves de firma del usuario
    priv_pem, pub_pem = ensure_user_sign_keys(email, user_secret)

    # 2) Crear el manifiesto del archivo
    manifest = {
        "filename": f.name,
        "size": len(data),
        "algo": "AES-GCM-256",
        "content_hash": content_hash,
    }

    # 3) Firmar el manifiesto → devuelve también el cert del usuario (b64url)
    sig_block = sign_manifest(email, user_secret, manifest)

    # 4) Verificar inmediatamente la firma usando el cert (PKI)
    ok_sig = verify_manifest_signature(manifest, sig_block["cert_pem"], sig_block["signature"])

    # 5) Mostrar resultado en la interfaz
    st.markdown("### Manifiesto firmado")
    st.json(manifest)
    st.markdown("### Firma generada")
    st.code(sig_block["signature"])
    st.success("✅ Firma verificada correctamente" if ok_sig else "❌ Error al verificar la firma")

    # ==========================
    # 💾 GUARDAR EN LOCAL POR USUARIO
    # ==========================
    DATA_DIR = os.getenv("STORAGE_PATH", "./_data")
    USER_DIR = os.path.join(DATA_DIR, "storage", email)
    os.makedirs(USER_DIR, exist_ok=True)

    base = secure_name(f.name)

    # 5.1 Guardar blob cifrado (nonce || ciphertext || tag) en binario
    enc_path = os.path.join(USER_DIR, base + ".enc")
    with open(enc_path, "wb") as out:
        out.write(nonce + ct + tag)

    # 5.2 Guardar metadatos: DEK envuelta, manifiesto y firma
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
        "dek_wrapped": {   # para recuperar la DEK con user_secret tras login
            "nonce": b64u(dek_nonce),
            "tag": b64u(dek_tag),
            "ct": b64u(dek_ct),
        },
        "manifest": manifest,   # lo que firmas
        "signature": sig_block, # incluye cert del usuario
    }
    meta_path = os.path.join(USER_DIR, base + ".meta.json")
    with open(meta_path, "w", encoding="utf-8") as out:
        json.dump(meta, out, indent=2, ensure_ascii=False)

    st.success(f"Guardado en: {enc_path}")
    st.caption(f"Sidecar: {meta_path}")

    # ==========================
    # 🪪 CERTIFICADO X.509 DEL USUARIO (PKI)
    # ==========================
    cert_pem = base64.urlsafe_b64decode(sig_block["cert_pem"] + "=" * (-len(sig_block["cert_pem"]) % 4))
    cert = x509.load_pem_x509_certificate(cert_pem)

    st.markdown("### 🪪 Certificado (X.509) adjunto")
    st.code(cert.public_bytes(encoding=serialization.Encoding.PEM).decode("utf-8"))

    # Campos clave: Subject (email), Issuer (CA), validez y huella
    subject = cert.subject.rfc4514_string()
    issuer = cert.issuer.rfc4514_string()
    nb = cert.not_valid_before
    na = cert.not_valid_after
    fp = cert.fingerprint(hashes.SHA256()).hex()

    st.write("**Subject (CN/email):**", subject)
    st.write("**Issuer (CA):**", issuer)
    st.write("**Validez:**", f"{nb} → {na}")
    st.write("**Fingerprint SHA-256:**", fp)

    # Validar el certificado contra la CA (usa cadena Usuario←AC2←AC1)
    st.write(
        "**Validación del certificado (contra CA local):**",
        "✅ OK" if pki_verify_cert(cert_pem) else "❌ FALLA",
    )

    # ==========================
    # 🔗 CADENA Usuario → AC2 → AC1 (visual)
    # ==========================
    CA_DIR = os.path.join(DATA_DIR, "ca")
    try:
        with open(os.path.join(CA_DIR, "subca_cert.pem"), "rb") as f:
            sub_cert = x509.load_pem_x509_certificate(f.read())
        with open(os.path.join(CA_DIR, "ca_cert.pem"), "rb") as f:
            root_cert = x509.load_pem_x509_certificate(f.read())

        st.markdown("### 🔗 Cadena de certificados")
        st.write("**User Issuer:**", cert.issuer.rfc4514_string())
        st.write("**SubCA Subject:**", sub_cert.subject.rfc4514_string())
        st.write("**SubCA Issuer:**", sub_cert.issuer.rfc4514_string())
        st.write("**Root Subject:**", root_cert.subject.rfc4514_string())
        st.info("Comprueba que: **User Issuer = SubCA Subject** y **SubCA Issuer = Root Subject**.")
    except FileNotFoundError:
        st.warning("No se encuentran los certificados de CA/SubCA en _data/ca/. ¿Inicializaste la PKI?")