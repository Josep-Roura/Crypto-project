from core import auth

def test_register_and_login_roundtrip(tmp_path, monkeypatch):
    # Redirige storage a tmp
    monkeypatch.setenv("STORAGE_PATH", str(tmp_path))
    # Reimport para tomar el nuevo STORAGE_PATH
    from importlib import reload
    reload(auth)

    ok, _, _ = auth.register_user("a@a.com", "secret123")
    assert ok

    ok, _, ctx, _ = auth.login("a@a.com", "secret123")
    assert ok
    assert "user_secret" in ctx and len(ctx["user_secret"]) == 32
