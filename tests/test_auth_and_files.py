import uuid
from typing import Dict


def _random_email() -> str:
    return f"test_{uuid.uuid4().hex[:8]}@example.com"


def _random_username() -> str:
    return f"user_{uuid.uuid4().hex[:8]}"


def _collect_user_id(register_data: Dict, login_data: Dict) -> str | None:
    return (login_data.get("id") or register_data.get("id") or register_data.get("user_id"))


def _auth_headers(user_id: str | None, login_data: Dict) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    if user_id:
        headers["X-User-Id"] = str(user_id)
    token = login_data.get("access_token")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


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


def test_register_login_and_upload_file(client):
    """
    Register + login + upload a simple text file.
    Accepts either token-based or header-based auth styles.
    """

    email = _random_email()
    username = _random_username()
    password = "uploadpassword123"

    register_payload: Dict[str, str] = {
        "email": email,
        "username": username,
        "password": password,
    }

    reg_resp = client.post("/api/auth/register", json=register_payload)
    assert reg_resp.status_code in (200, 201), reg_resp.text
    reg_data = reg_resp.json()

    login_resp = client.post(
        "/api/auth/login",
        json={"username": username, "password": password},
    )
    assert login_resp.status_code == 200, login_resp.text
    login_data = login_resp.json()

    user_id = _collect_user_id(reg_data, login_data)
    headers = _auth_headers(user_id, login_data)

    # Ensure crypto keys exist for the uploader
    keys_resp = client.post("/api/keys/me", headers=headers)
    assert keys_resp.status_code in (200, 201, 400), keys_resp.text

    files = {"uploaded_file": ("hello.txt", b"hello world", "text/plain")}
    upload_resp = client.post("/api/files", headers=headers, files=files)
    assert upload_resp.status_code in (200, 201), upload_resp.text
    upload_data = upload_resp.json()
    assert isinstance(upload_data, dict)
    if "filename" in upload_data:
        assert upload_data.get("filename") == "hello.txt"


def test_upload_binary_file_without_utf8_error(client):
    """
    Uploads a binary payload and ensures no UnicodeDecodeError or 5xx responses occur.
    """

    email = _random_email()
    username = _random_username()
    password = "binarypassword123"

    reg_resp = client.post(
        "/api/auth/register",
        json={"email": email, "username": username, "password": password},
    )
    assert reg_resp.status_code in (200, 201), reg_resp.text
    reg_data = reg_resp.json()

    login_resp = client.post(
        "/api/auth/login",
        json={"username": username, "password": password},
    )
    assert login_resp.status_code == 200, login_resp.text
    login_data = login_resp.json()

    user_id = _collect_user_id(reg_data, login_data)
    headers = _auth_headers(user_id, login_data)

    keys_resp = client.post("/api/keys/me", headers=headers)
    assert keys_resp.status_code in (200, 201, 400), keys_resp.text

    binary_content = b"\x8e\xff\x00\x01binarydata"
    files = {"uploaded_file": ("binary.bin", binary_content, "application/octet-stream")}
    upload_resp = client.post("/api/files", headers=headers, files=files)
    assert upload_resp.status_code in (200, 201), upload_resp.text
    body_text = upload_resp.text
    assert "UnicodeDecodeError" not in body_text
