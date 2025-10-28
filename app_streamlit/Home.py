# --------------------------------------------------------------
# File: Home.py
# Description: Define la página principal de Streamlit con el resumen del flujo.
# --------------------------------------------------------------

import streamlit as st

# Configura los metadatos de la página principal de la aplicación.
st.set_page_config(page_title="Crypto Drive", page_icon="🔐", layout="centered")

# Presenta el nombre del producto y su propósito general.
st.title("🔐 Crypto Drive")
st.write("MVP para subir, cifrar y gestionar archivos con AES-GCM + autenticación de usuarios.")
st.info("Primero ve a **Registro y Login** para crear tu cuenta y desbloquear sesión.")
