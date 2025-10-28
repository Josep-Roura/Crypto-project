# --------------------------------------------------------------
# File: test_auth_flow.py
# Description: Pruebas de integración del registro y login sobre el módulo core.auth.
# --------------------------------------------------------------

from core import auth


def test_register_and_login_happy_path():
    """Valida el flujo exitoso de registro seguido de un login válido.

    Returns:
        None: Las aserciones internas verifican el comportamiento esperado.
    """
    ok, msg, dbg = auth.register_user("a@b.com", "Str0ng_P@ssword123!")
    assert ok, msg

    ok2, msg2, ctx, dbg2 = auth.login("a@b.com", "Str0ng_P@ssword123!")
    assert ok2, msg2
    assert ctx["email"] == "a@b.com"
    assert isinstance(ctx["user_secret"], (bytes, bytearray))
    assert len(ctx["user_secret"]) == 32  # 256 bits


def test_register_rejects_existing():
    """Comprueba que no se permitan registros duplicados para el mismo correo.

    Returns:
        None: Se utilizan aserciones para validar el rechazo.
    """
    auth.register_user("dup@x.com", "Str0ng_P@ssword123!")
    ok, msg, dbg = auth.register_user("dup@x.com", "Str0ng_P@ssword123!")
    assert not ok
    assert "existe" in msg.lower()


def test_register_rejects_weak_passphrase():
    """Garantiza que las passphrases débiles sean rechazadas al registrarse.

    Returns:
        None: Las aserciones aseguran la correcta validación de la política.
    """
    ok, msg, dbg = auth.register_user("w@k.com", "weakweakweak")
    assert not ok
    assert "no es suficientemente robusta" in msg.lower()


def test_login_wrong_password():
    """Verifica que un login con passphrase incorrecta sea denegado.

    Returns:
        None: Las aserciones confirman el mensaje de error esperado.
    """
    auth.register_user("a@b.com", "Str0ng_P@ssword123!")
    ok, msg, ctx, dbg = auth.login("a@b.com", "wrong-pass")
    assert not ok
    assert "incorrecta" in msg.lower() or "error" in msg.lower()


def test_persistence_user_secret_after_restart():
    """Confirma que el secreto de usuario persiste cifrado entre sesiones.

    Returns:
        None: Las aserciones comparan los secretos recuperados.
    """
    auth.register_user("p@q.com", "Str0ng_P@ssword123!")
    ok1, _, ctx1, _ = auth.login("p@q.com", "Str0ng_P@ssword123!")
    ok2, _, ctx2, _ = auth.login("p@q.com", "Str0ng_P@ssword123!")
    assert ok1 and ok2
    assert ctx1["user_secret"] == ctx2["user_secret"]
