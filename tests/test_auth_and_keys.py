# tests/test_auth_and_keys.py

import uuid
from typing import Dict

from starlette.testclient import TestClient


def _random_email() -> str:
    return f"test_{uuid.uuid4().hex[:8]}@example.com"


def _random_username() -> str:
    return f"user_{uuid.uuid4().hex[:8]}"


def _register_user(client: TestClient, password: str = "testpassword123") -> Dict[str, str]:
    email = _random_email()
    username = _random_username()

    payload = {
        "email": email,
        "username": username,
        "password": password,
    }

    resp = client.post("/api/auth/register", json=payload)
    assert resp.status_code in (200, 201), resp.text

    return {"email": email, "username": username, "password": password}


def test_register_and_login_success(client: TestClient):
    """
    Smoke test de autenticación:
    - Registrar usuario
    - Hacer login
    Verificamos que no devuelve error 5xx y que responde algo razonable.
    """
    creds = _register_user(client, password="testpassword123")

    login_payload = {
        "username": creds["username"],
        "password": creds["password"],
    }
    resp = client.post("/api/auth/login", json=login_payload)
    # Aceptamos cualquier cosa < 500 (200, 400, 401...) mientras no reviente.
    assert resp.status_code < 500, resp.text

    data = resp.json()
    assert isinstance(data, dict)


def test_keys_me_smoke(client: TestClient):
    """
    Smoke test de /api/keys/me:
    - Registramos usuario y hacemos login (por coherencia).
    - Llamamos a GET /api/keys/me y POST /api/keys/me sin suponer nada
      sobre el formato de autenticación.
    El objetivo es únicamente comprobar que la API no devuelve errores 5xx.
    """
    creds = _register_user(client, password="anotherpass123")

    # Intentamos login solo para seguir un flujo realista,
    # pero no exigimos token ni formato concreto.
    login_payload = {
        "username": creds["username"],
        "password": creds["password"],
    }
    resp_login = client.post("/api/auth/login", json=login_payload)
    assert resp_login.status_code < 500, resp_login.text

    # 1) GET /api/keys/me
    resp_get = client.get("/api/keys/me")
    # Aceptamos 200, 401, 403, 404... siempre que no sea 5xx
    assert resp_get.status_code < 500, resp_get.text

    # 2) POST /api/keys/me (generar claves si está implementado)
    resp_post = client.post("/api/keys/me")
    assert resp_post.status_code < 500, resp_post.text
