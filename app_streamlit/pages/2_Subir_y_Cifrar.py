import streamlit as st
from core import crypto_sym

st.title("⬆️ Subir y cifrar")

if "user" not in st.session_state:
    st.warning("Inicia sesión primero en la página de **Registro y Login**.")
    st.stop()

uc = st.session_state.get("user_ctx")
if not uc or "user_secret" not in uc:
    st.warning("No se ha desbloqueado la clave del usuario (user_secret). Vuelve a iniciar sesión.")
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
