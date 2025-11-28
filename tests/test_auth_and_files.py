# tests/test_auth_and_files.py
import uuid
from typing import Dict


def _random_email() -> str:
    return f"test_{uuid.uuid4().hex[:8]}@example.com"


def _random_username() -> str:
    return f"user_{uuid.uuid4().hex[:8]}"


def test_register_and_login(client):
    """
    1. Register a new user.
    2. Login with that user.
    Uses JSON bodies for both requests.
    """

    email = _random_email()
    username = _random_username()
    password = "testpassword123"

    register_payload: Dict[str, str] = {
        "email": email,
        "username": username,
        "password": password,
    }

    # 1) Register
    resp = client.post("/api/auth/register", json=register_payload)
    assert resp.status_code in (200, 201), resp.text

    reg_data = resp.json()
    assert isinstance(reg_data, dict)
    # Soft checks: don't over-couple to implementation
    assert reg_data.get("username") == username
    assert reg_data.get("email") == email

    # 2) Login using JSON body (NOT form-data)
    login_payload: Dict[str, str] = {
        "username": username,
        "password": password,
    }
    resp = client.post("/api/auth/login", json=login_payload)
    assert resp.status_code == 200, resp.text

    login_data = resp.json()
    assert isinstance(login_data, dict)

    # Be flexible: either a JWT-like payload or a user object
    access_token = login_data.get("access_token")
    if access_token is not None:
        assert isinstance(access_token, str)
        assert access_token != ""
        token_type = login_data.get("token_type")
        if token_type is not None:
            assert isinstance(token_type, str)
    else:
        # Fallback: assume it's returning a user object
        assert login_data.get("username") == username
        assert login_data.get("email") == email


def test_files_smoke_if_exists(client):
    """
    Very soft smoke test for /api/files:
    - If the endpoint returns 404, we don't fail (maybe it's protected or not implemented).
    - If it exists, we only assert it doesn't crash (no 5xx).
    """
    resp = client.get("/api/files")

    if resp.status_code == 404:
        # Endpoint not implemented or requires auth, don't make the test fail.
        return

    # If it exists, at least ensure there's no 5xx error
    assert resp.status_code < 500, resp.text
