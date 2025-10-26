import os
import json
import base64
import streamlit as st

from core.crypto_sym import aes_gcm_decrypt_with_key
from api.services import verify_manifest_signature
from api.pki import pki_verify_cert

from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes


st.title("📥 Descargar y descifrar")

# ---- helpers ----
def _unb64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def _user_dir(email: str) -> str:
    data_dir = os.getenv("STORAGE_PATH", "./_data")
    return os.path.join(data_dir, "storage", email)

def _list_meta_files(user_dir: str):
    if not os.path.isdir(user_dir):
        return []
    return sorted([f for f in os.listdir(user_dir) if f.endswith(".meta.json")])

# ---- sesión ----
uc = st.session_state.get("user_ctx")
if not uc or "email" not in uc or "user_secret" not in uc:
    st.warning("Inicia sesión primero en **Registro y Login**.")
    st.stop()

email = uc["email"]
user_secret = uc["user_secret"]
user_dir = _user_dir(email)

st.write("Carpeta del usuario:", f"`{user_dir}`")

meta_files = _list_meta_files(user_dir)
if not meta_files:
    st.info("No hay archivos almacenados aún. Ve a **Subir y Cifrar** para añadir alguno.")
    st.stop()

sel = st.selectbox("Selecciona un archivo (por su .meta.json):", meta_files, index=0)

# ---- cargar meta ----
meta_path = os.path.join(user_dir, sel)
with open(meta_path, "r", encoding="utf-8") as f:
    meta = json.load(f)

enc_path = os.path.join(user_dir, meta["stored_as"])

col1, col2 = st.columns(2)
with col1:
    st.write("**Nombre original:**", meta.get("original_filename"))
    st.write("**Guardado como:**", meta.get("stored_as"))
    st.write("**Algoritmo:**", meta.get("algo"))
with col2:
    st.write("**Tamaño cifrado (ct_len):**", meta["ciphertext"]["length"])
    st.write("**Nonce (b64u):**", meta["ciphertext"]["nonce"])
    st.write("**Tag (b64u):**", meta["ciphertext"]["tag"])

st.markdown("### 📝 Manifiesto")
st.json(meta["manifest"])

st.markdown("### ✍️ Firma + Certificado")
sig_block = meta["signature"]
st.code(sig_block["signature"], language="text")

# Mostrar certificado
cert_pem = _unb64u(sig_block["cert_pem"])
cert = x509.load_pem_x509_certificate(cert_pem)
st.code(cert.public_bytes(serialization.Encoding.PEM).decode("utf-8"))

# Verificaciones
ok_cert = pki_verify_cert(cert_pem)
ok_sig = verify_manifest_signature(meta["manifest"], sig_block["cert_pem"], sig_block["signature"])

st.write("**Certificado válido (cadena Usuario→AC2→AC1):**", "✅ OK" if ok_cert else "❌ FALLA")
st.write("**Firma sobre manifiesto:**", "✅ OK" if ok_sig else "❌ FALLA")

# ---- botones de descarga ----
# 1) Descargar cifrado tal cual (.enc)
with open(enc_path, "rb") as f:
    enc_blob = f.read()
st.download_button(
    "⬇️ Descargar archivo cifrado (.enc)",
    data=enc_blob,
    file_name=os.path.basename(enc_path),
    mime="application/octet-stream",
)

# 2) Descifrar (con user_secret → unwrap DEK → AES-GCM) y descargar original
if st.button("🔓 Descifrar y preparar descarga del original"):
    try:
        # recuperar DEK
        dek_wr = meta["dek_wrapped"]
        DEK = aes_gcm_decrypt_with_key(
            user_secret,
            _unb64u(dek_wr["nonce"]),
            _unb64u(dek_wr["ct"]),
            _unb64u(dek_wr["tag"]),
        )

        # separar nonce|ct|tag del blob .enc
        nonce = enc_blob[:12]
        tag = enc_blob[-16:]
        ct = enc_blob[12:-16]

        # descifrar
        plaintext = aes_gcm_decrypt_with_key(DEK, nonce, ct, tag)

        # ofrecer descarga
        st.success("Archivo descifrado correctamente.")
        st.download_button(
            "⬇️ Descargar archivo original",
            data=plaintext,
            file_name=meta.get("original_filename") or "archivo_recuperado",
            mime="application/octet-stream",
        )

        # info adicional
        st.caption(f"SHA-256 del claro: {hashes.Hash(hashes.SHA256()).copy().algorithm.name if False else ''}")
    except Exception as e:
        st.error(f"Error descifrando: {e}")