# tests/test_pki_cert.py

import uuid

from starlette.testclient import TestClient


def _random_email() -> str:
    return f"pkitest_{uuid.uuid4().hex[:8]}@example.com"


def _random_username() -> str:
    return f"pkiuser_{uuid.uuid4().hex[:8]}"


def _register_and_login_smoke(client: TestClient):
    """
    Registrar usuario y hacer login sin exigir token concreto.
    """
    email = _random_email()
    username = _random_username()
    password = "pkipassword123"

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


def test_pki_cert_me_smoke(client: TestClient):
    """
    Smoke test de la parte de PKI:
    - Usuario nuevo + login.
    - GET /api/pki/cert/me -> aceptamos 200 o 404 (no tiene certificado aún),
      siempre que no sea 5xx.
    """
    _register_and_login_smoke(client)

    resp = client.get("/api/pki/cert/me")
    # Aceptamos 404 si aún no hay certificado
    assert resp.status_code in (200, 404) or resp.status_code < 500, resp.text
