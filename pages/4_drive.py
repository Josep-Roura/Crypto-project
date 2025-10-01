import io, json, time
import streamlit as st
from cipherlab.core.storage import (
    init_db, get_user_by_username, list_files_for_user, create_file,
    get_conn, add_file_blob, get_latest_blob, add_acl, remove_acl, audit
)
from cipherlab.core.drive import encrypt_file_bytes, decrypt_file_bytes, save_ciphertext, load_ciphertext

st.set_page_config(page_title="Drive", page_icon="🔐")
init_db()

if "user" not in st.session_state or not st.session_state.user:
    st.error("Acceso restringido. Inicia sesión primero."); st.stop()

username = st.session_state.user
st.title("🔐 Drive seguro (MVP)")
st.caption("Sube, comparte y descarga tus archivos con control de acceso.")

# === Subida ===
st.subheader("Subir archivo")
file = st.file_uploader("Selecciona un archivo", type=None)
if file is not None:
    data = file.read()
    manifest, ct = encrypt_file_bytes(data, file.name)
    owner = get_user_by_username(username)
    file_id = create_file(owner.id, file.name, len(data))

    conn = get_conn()
    cur = conn.execute("SELECT MAX(version) FROM file_blobs WHERE file_id = ?", (file_id,))
    row = cur.fetchone(); version = (row[0] if row and row[0] is not None else 0) + 1
    conn.close()

    path = save_ciphertext(file_id, version, ct)
    add_file_blob(file_id, version, json.dumps(manifest), path)
    audit(username, "upload", file_id, {"version": version, "name": file.name, "size": len(data)})
    st.success(f"Archivo subido como versión v{version}.")

st.divider()

# === Listado ===
st.subheader("Tus archivos y compartidos contigo")
me = get_user_by_username(username)
files = list_files_for_user(me.id)
if not files:
    st.info("Aún no hay archivos.")
else:
    for f in files:
        with st.container(border=True):
            st.markdown(f"**{f['name']}** · {f['size']} bytes · {time.strftime('%Y-%m-%d %H:%M', time.localtime(f['created_at']))}")
            c1, c2, c3 = st.columns(3)

            # Descargar
            with c1:
                if st.button("Descargar", key=f"dl_{f['id']}"):
                    row = get_latest_blob(f["id"])
                    if not row:
                        st.error("No hay versiones disponibles.")
                    else:
                        version, manifest_json, path = row
                        manifest = json.loads(manifest_json)
                        ct = load_ciphertext(path)
                        try:
                            pt = decrypt_file_bytes(manifest, ct)
                            st.download_button("Guardar archivo", data=pt, file_name=manifest["name"], mime="application/octet-stream", key=f"db_{f['id']}")
                        except Exception:
                            st.error("No se pudo abrir el archivo.")

            # Compartir (añadir ACL)
            with c2:
                with st.popover("Compartir con usuario"):
                    u = st.text_input("Usuario destino", key=f"user_{f['id']}")
                    if st.button("Compartir", key=f"share_{f['id']}"):
                        dest = get_user_by_username(u)
                        if not dest:
                            st.error("Usuario no encontrado.")
                        else:
                            add_acl(f["id"], dest.id)
                            audit(username, "share", f["id"], {"to": u})
                            st.success(f"Compartido con {u}.")

            # Quitar acceso
            with c3:
                with st.popover("Quitar acceso"):
                    u2 = st.text_input("Usuario a quitar", key=f"rm_{f['id']}")
                    if st.button("Quitar", key=f"rm_btn_{f['id']}"):
                        dest = get_user_by_username(u2)
                        if not dest:
                            st.error("Usuario no encontrado.")
                        else:
                            remove_acl(f["id"], dest.id)
                            audit(username, "revoke_access", f["id"], {"to": u2})
                            st.success(f"Acceso quitado a {u2}.")
