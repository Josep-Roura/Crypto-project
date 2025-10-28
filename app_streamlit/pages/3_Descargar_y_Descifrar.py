# --------------------------------------------------------------
# File: 3_Descargar_y_Descifrar.py
# Description: Permite recuperar archivos cifrados y descifrarlos desde Streamlit.
# --------------------------------------------------------------

import base64
import hashlib
import json
import os
from typing import List

import streamlit as st
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from api.pki import pki_verify_cert
from api.services import verify_manifest_signature
from core.crypto_sym import aes_gcm_decrypt_with_key


def _unb64u(value: str) -> bytes:
    """Decodifica una cadena en base64 url-safe sin relleno.

    Args:
        value (str): Texto en base64 url-safe proveniente de los metadatos.

    Returns:
        bytes: Representación binaria decodificada.
    """
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _user_dir(email: str) -> str:
    """Calcula la ruta de almacenamiento asociada a un usuario.

    Args:
        email (str): Correo electrónico del usuario autenticado.

    Returns:
        str: Ruta absoluta hacia la carpeta del usuario.
    """
    data_dir = os.getenv("STORAGE_PATH", "./_data")
    return os.path.join(data_dir, "storage", email)


def _list_meta_files(user_dir: str) -> List[str]:
    """Devuelve la lista de manifiestos disponibles para un usuario.

    Args:
        user_dir (str): Ruta del directorio de almacenamiento del usuario.

    Returns:
        List[str]: Archivos `.meta.json` ordenados alfabéticamente.
    """
    if not os.path.isdir(user_dir):
        return []
    return sorted([f for f in os.listdir(user_dir) if f.endswith(".meta.json")])


# Presenta el título de la sección orientada a la restauración.
st.title("📥 Descargar y descifrar")

# Comprueba que exista contexto autenticado antes de acceder a los datos.
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

# Carga el manifiesto asociado al archivo seleccionado.
meta_path = os.path.join(user_dir, sel)
with open(meta_path, "r", encoding="utf-8") as handler:
    meta = json.load(handler)

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

st.markdown("### Manifiesto")
st.json(meta["manifest"])

st.markdown("### Firma + Certificado")
sig_block = meta["signature"]
st.code(sig_block["signature"], language="text")

# Muestra y valida el certificado del usuario asociado a la firma.
cert_pem = _unb64u(sig_block["cert_pem"])
cert = x509.load_pem_x509_certificate(cert_pem)
st.code(cert.public_bytes(serialization.Encoding.PEM).decode("utf-8"))

# Ejecuta las comprobaciones de la cadena de confianza y de la firma.
ok_cert = pki_verify_cert(cert_pem)
ok_sig = verify_manifest_signature(meta["manifest"], sig_block["cert_pem"], sig_block["signature"])

st.write("**Certificado válido (cadena Usuario→AC2→AC1):**", "✅ OK" if ok_cert else "❌ FALLA")
st.write("**Firma sobre manifiesto:**", "✅ OK" if ok_sig else "❌ FALLA")

# Permite descargar directamente el blob cifrado.
with open(enc_path, "rb") as enc_handler:
    enc_blob = enc_handler.read()
st.download_button(
    "⬇️ Descargar archivo cifrado (.enc)",
    data=enc_blob,
    file_name=os.path.basename(enc_path),
    mime="application/octet-stream",
)

# Ofrece el descifrado local y la descarga del contenido en claro.
if st.button("🔓 Descifrar y preparar descarga del original"):
    try:
        dek_wr = meta["dek_wrapped"]
        dek = aes_gcm_decrypt_with_key(
            user_secret,
            _unb64u(dek_wr["nonce"]),
            _unb64u(dek_wr["ct"]),
            _unb64u(dek_wr["tag"]),
        )

        nonce = enc_blob[:12]
        tag = enc_blob[-16:]
        ciphertext = enc_blob[12:-16]

        plaintext = aes_gcm_decrypt_with_key(dek, nonce, ciphertext, tag)

        st.success("Archivo descifrado correctamente.")
        st.download_button(
            "⬇️ Descargar archivo original",
            data=plaintext,
            file_name=meta.get("original_filename") or "archivo_recuperado",
            mime="application/octet-stream",
        )

        sha256 = hashlib.sha256(plaintext).hexdigest()
        st.caption(f"SHA-256 del claro: {sha256}")
    except Exception as exc:
        st.error(f"Error descifrando: {exc}")
