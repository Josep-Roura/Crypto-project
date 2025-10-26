import streamlit as st
from core import crypto_sym
from api.services import ensure_user_sign_keys, sign_manifest, verify_manifest_signature
import hashlib
from api.pki import pki_verify_cert
from cryptography import x509
from cryptography.hazmat.primitives import hashes
import base64
from cryptography.hazmat.primitives import serialization

st.title("⬆️ Subir y cifrar")



uc = st.session_state.get("user_ctx")
if not uc or "email" not in uc or "user_secret" not in uc:
    st.warning("Inicia sesión primero en la página de **Registro y Login**.")
    st.stop()

f = st.file_uploader("Selecciona un archivo", type=None)
if f and st.button("Cifrar con AES-GCM"):
    data = f.read()
    res = crypto_sym.encrypt_aes_gcm(data)
    st.success("Archivo cifrado.")
    st.code(
        f"AES-GCM-256 | nonce={len(res.nonce)*8} bits | tag={len(res.tag)*8} bits\n"
        f"ct_len={len(res.ciphertext)} bytes"
    )

    # ==========================
    # 🔒 FIRMA DIGITAL (PUNTO 4)
    # ==========================
    email = uc["email"]
    user_secret = uc["user_secret"]

    # Calcular hash del archivo
    content_hash = "sha256:" + hashlib.sha256(data).hexdigest()

    # 1 Generar o recuperar las claves de firma
    priv_pem, pub_pem = ensure_user_sign_keys(email, user_secret)

    # 2 Crear el manifiesto del archivo
    manifest = {
        "filename": f.name,
        "size": len(data),
        "algo": "AES-GCM-256",
        "content_hash": content_hash,
    }

    # 3 Firmar el manifiesto
    sig_block = sign_manifest(email, user_secret, manifest)

    # 4 Verificar inmediatamente la firma
    ok_sig = verify_manifest_signature(manifest, sig_block["cert_pem"], sig_block["signature"])

    # 5 Mostrar resultado en la interfaz
    st.markdown("### Manifiesto firmado")
    st.json(manifest)
    st.markdown("### Firma generada")
    st.code(sig_block["signature"])
    st.success(" Firma verificada correctamente" if ok_sig else " Error al verificar la firma")


    # Mostrar detalles del certificado adjunto
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
    st.write("**Validez:**", f"{nb}  →  {na}")
    st.write("**Fingerprint SHA-256:**", fp)

    # Validar el certificado contra la CA
    st.write("**Validación del certificado (contra CA local):**",
            "✅ OK" if pki_verify_cert(cert_pem) else "❌ FALLA")