# --------------------------------------------------------------
# File: 1_Registro_y_Login.py
# Description: Implementa las vistas de registro y autenticación en Streamlit.
# --------------------------------------------------------------

import streamlit as st

from core import auth
from core.password_policy import check_passphrase_strength

# Presenta el título general de la página.
st.title("👤 Registro y Login")

# Separa la pantalla en pestañas para registro y autenticación.
tab_reg, tab_log = st.tabs(["Registro", "Login"])

# Sección de registro de nuevas cuentas.
with tab_reg:
    email = st.text_input("Email", key="reg_email")
    passphrase = st.text_input(
        "Passphrase",
        type="password",
        key="reg_pass",
        help=(
            "Requisitos: mínimo 12 caracteres, al menos 3 de 4 clases "
            "(minúsculas, mayúsculas, dígitos, símbolos), sin espacios, "
            "sin repeticiones largas y sin incluir partes del email."
        ),
    )


    ok_pw, reasons, score = (False, [], 0)
    if passphrase:
        # Evalúa la fortaleza de la passphrase con la política definida.
        ok_pw, reasons, score = check_passphrase_strength(passphrase, email=email)
        st.progress(score / 100.0, text=f"Fortaleza estimada: {score}/100")
        if not ok_pw:
            st.warning("Mejoras recomendadas:\n- " + "\n- ".join(reasons))


    disabled = (not email) or (not passphrase) or (not ok_pw)

    if st.button("Crear cuenta", disabled=disabled, key="btn_register"):
        ok, msg, dbg = auth.register_user(email, passphrase)
        if ok:
            st.success(msg)
            st.code(dbg)
        else:
            st.error(msg)

# Sección de inicio de sesión para usuarios existentes.
with tab_log:
    email_l = st.text_input("Email", key="log_email")
    passphrase_l = st.text_input("Passphrase", type="password", key="log_pass")

    if st.button("Iniciar sesión", key="btn_login"):
        ok, msg, ctx, dbg = auth.login(email_l, passphrase_l)
        if ok:
            # SECURITY: Conserva el contexto autenticado incluido el secreto derivado.
            st.session_state["user_ctx"] = {
                "email": email_l,
                "user_secret": ctx["user_secret"],
            }
            st.success(msg)
            st.code(dbg)
        else:
            st.error(msg)
