import streamlit as st
from core import auth

st.title("👤 Registro y Login")

tab_reg, tab_log = st.tabs(["Registro", "Login"])

with tab_reg:
    email = st.text_input("Email", key="reg_email")
    passphrase = st.text_input("Passphrase", type="password", key="reg_pass")
    if st.button("Crear cuenta"):
        ok, msg, dbg = auth.register_user(email, passphrase)
        if ok:
            st.success(msg)
            st.code(dbg)
        else:
            st.error(msg)

with tab_log:
    email_l = st.text_input("Email", key="log_email")
    passphrase_l = st.text_input("Passphrase", type="password", key="log_pass")
    if st.button("Iniciar sesión"):
        ok, msg, ctx, dbg = auth.login(email_l, passphrase_l)
        if ok:
            
            st.session_state["user_ctx"] = {
                "email": email_l,
                "user_secret": ctx["user_secret"],
}
            st.success(msg)
            st.code(dbg)
        else:
            st.error(msg)
