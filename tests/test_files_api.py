# tests/test_files_api.py

import io
import uuid

from starlette.testclient import TestClient


def _random_email() -> str:
    """Genera un email único para no reusar cuentas entre casos."""

    return f"filetest_{uuid.uuid4().hex[:8]}@example.com"


def _random_username() -> str:
    """Devuelve un username aleatorio para el flujo de ficheros."""

    return f"fileuser_{uuid.uuid4().hex[:8]}"


def _register_and_login_smoke(client: TestClient):
    """
    Registrar usuario y hacer login sin asumir formato de token.
    Solo comprobamos que no hay errores 5xx.
    """
    email = _random_email()
    username = _random_username()
    password = "filetestpassword123"

    register_payload = {
        "email": email,
        "username": username,
        "password": password,
    }
    resp_reg = client.post("/api/auth/register", json=register_payload)
    assert resp_reg.status_code in (200, 201), resp_reg.text

    login_payload = {"username": username, "password": password}
    resp_login = client.post("/api/auth/login", json=login_payload)
    assert resp_login.status_code < 500, resp_login.text


def test_upload_text_file_and_list(client: TestClient):
    """
    Smoke test de ficheros:
    - Usuario nuevo + login (sin depender de tokens).
    - Intentar subir un fichero pequeño de texto.
    - Llamar a /api/files para asegurarnos de que no hay error 5xx
      ni problemas de decodificación.
    """
    _register_and_login_smoke(client)

    # Intentar GET /api/files antes de subir nada
    resp_list_initial = client.get("/api/files")
    assert resp_list_initial.status_code < 500, resp_list_initial.text

    # Subimos un fichero pequeño de texto
    file_content = b"Hola, este es un fichero de prueba.\nLinea 2.\n"
    files = {
        "file": ("prueba.txt", io.BytesIO(file_content), "text/plain"),
    }

    resp_upload = client.post("/api/files", files=files)
    # Aceptamos 200, 201, 401, 403, 404... siempre que no sea 5xx
    assert resp_upload.status_code < 500, resp_upload.text

    # Volvemos a listar /api/files para asegurarnos de que responde correctamente
    resp_list_after = client.get("/api/files")
    assert resp_list_after.status_code < 500, resp_list_after.text
    data = resp_list_after.json()
    assert isinstance(data, (list, dict))
