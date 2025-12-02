# tests/test_auth_files.py

"""
Pruebas de humo para los endpoints de ficheros combinados con autenticación.
Las aserciones solo verifican que el backend responde sin errores 5xx aunque
las rutas devuelvan 2xx/4xx dependiendo de si requieren credenciales.
"""

import io
import uuid

from starlette.testclient import TestClient


def _random_email() -> str:
    """Genera un email único para aislar casos de subida y descarga."""

    return f"authfiles_{uuid.uuid4().hex[:8]}@example.com"


def _random_username() -> str:
    """Crea un username aleatorio para no mezclar usuarios entre escenarios."""

    return f"authfiles_user_{uuid.uuid4().hex[:8]}"


def _register_user(client: TestClient, password: str = "filepass123"):
    """
    Registra un usuario base para probar flujos de ficheros.

    No asumimos esquema de tokens ni cookies: solo validamos que las rutas
    respondan sin reventar ante registros y logins mínimos.
    """

    payload = {
        "email": _random_email(),
        "username": _random_username(),
        "password": password,
    }
    resp = client.post("/api/auth/register", json=payload)
    assert resp.status_code in (200, 201), resp.text

    return payload


def test_list_files_without_login(client: TestClient):
    """
    Smoke del listado sin autenticación: GET /api/files sin cabeceras.
    Aceptamos 2xx/4xx siempre que no haya 5xx ni tracebacks en la respuesta.
    """

    resp = client.get("/api/files")
    assert resp.status_code < 500, resp.text



def test_upload_small_file_after_login(client: TestClient):
    """
    Flujo de subida con credenciales recién creadas:
    - Registrar usuario y hacer login para seguir un camino realista.
    - Subir un fichero de texto pequeño a /api/files.
    - Validar que el backend responde con algo distinto de 5xx aunque
      el sistema requiera tokens o políticas de autorización.
    """

    user = _register_user(client)

    login_payload = {"username": user["username"], "password": user["password"]}
    resp_login = client.post("/api/auth/login", json=login_payload)
    assert resp_login.status_code < 500, resp_login.text

    file_content = b"Fichero de prueba para flujo autenticado.\n"
    files = {"file": ("authtest.txt", io.BytesIO(file_content), "text/plain")}

    resp_upload = client.post("/api/files", files=files)
    assert resp_upload.status_code < 500, resp_upload.text



def test_download_unknown_file_is_safe(client: TestClient):
    """
    Descarga de un id aleatorio para comprobar que el backend responde con
    4xx esperado en vez de lanzar un 5xx que rompa la app.
    """

    random_id = uuid.uuid4()
    resp = client.get(f"/api/files/{random_id}")
    assert resp.status_code < 500, resp.text
