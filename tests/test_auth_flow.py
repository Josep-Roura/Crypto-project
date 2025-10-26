# tests/test_auth_flow.py
from core import auth

def test_register_and_login_happy_path():
    ok, msg, dbg = auth.register_user("a@b.com", "Str0ng_P@ssword123!")
    assert ok, msg

    ok2, msg2, ctx, dbg2 = auth.login("a@b.com", "Str0ng_P@ssword123!")
    assert ok2, msg2
    assert ctx["email"] == "a@b.com"
    assert isinstance(ctx["user_secret"], (bytes, bytearray))
    assert len(ctx["user_secret"]) == 32  # 256-bit

def test_register_rejects_existing():
    auth.register_user("dup@x.com", "Str0ng_P@ssword123!")
    ok, msg, dbg = auth.register_user("dup@x.com", "Str0ng_P@ssword123!")
    assert not ok
    assert "existe" in msg.lower()

def test_register_rejects_weak_passphrase():
    ok, msg, dbg = auth.register_user("w@k.com", "weakweakweak")
    assert not ok
    assert "no es suficientemente robusta" in msg.lower()

def test_login_wrong_password():
    auth.register_user("a@b.com", "Str0ng_P@ssword123!")
    ok, msg, ctx, dbg = auth.login("a@b.com", "wrong-pass")
    assert not ok
    assert "incorrecta" in msg.lower() or "error" in msg.lower()

def test_persistence_user_secret_after_restart():
    # Dos logins separados deben descifrar el MISMO user_secret almacenado cifrado
    auth.register_user("p@q.com", "Str0ng_P@ssword123!")
    ok1, _, ctx1, _ = auth.login("p@q.com", "Str0ng_P@ssword123!")
    ok2, _, ctx2, _ = auth.login("p@q.com", "Str0ng_P@ssword123!")
    assert ok1 and ok2
    assert ctx1["user_secret"] == ctx2["user_secret"]