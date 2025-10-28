# --------------------------------------------------------------
# File: test_pki.py
# Description: Pruebas de la infraestructura PKI local y emisión de certificados.
# --------------------------------------------------------------

import importlib
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


def _reload_pki(monkeypatch, storage_dir: Path):
    """Recarga el módulo api.pki tras fijar STORAGE_PATH.

    Args:
        monkeypatch (pytest.MonkeyPatch): Fixture para modificar variables de entorno.
        storage_dir (Path): Ruta temporal que alojará la jerarquía de la PKI.

    Returns:
        ModuleType: Referencia al módulo api.pki recargado.
    """
    monkeypatch.setenv("STORAGE_PATH", str(storage_dir))
    import api.pki as pki

    return importlib.reload(pki)


def _gen_user_pub_pem():
    """Genera un par Ed25519 y devuelve el PEM público.

    Returns:
        tuple[ed25519.Ed25519PrivateKey, bytes]: Clave privada y PEM de la clave pública.
    """
    sk = ed25519.Ed25519PrivateKey.generate()
    pk = sk.public_key()
    pub_pem = pk.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return sk, pub_pem


def test_pki_chain_ok_ed25519(tmp_path, monkeypatch):
    """Verifica que la cadena Usuario→SubCA→Root se valide correctamente.

    Args:
        tmp_path (Path): Carpeta temporal para la PKI.
        monkeypatch (pytest.MonkeyPatch): Fixture para ajustar el entorno.

    Returns:
        None: Las aserciones comprueban la verificación satisfactoria.
    """
    d1 = tmp_path / "ca1"
    d1.mkdir()
    pki = _reload_pki(monkeypatch, d1)

    _, pub_pem = _gen_user_pub_pem()
    cert_pem = pki.pki_issue_user_cert("user@example.com", pub_pem)

    assert pki.pki_verify_cert(cert_pem) is True


def test_pki_chain_fails_with_wrong_root(tmp_path, monkeypatch):
    """Comprueba que certificados emitidos por otra raíz no validen.

    Args:
        tmp_path (Path): Carpeta temporal para las jerarquías.
        monkeypatch (pytest.MonkeyPatch): Fixture para controlar STORAGE_PATH.

    Returns:
        None: Las aserciones verifican el rechazo al cambiar la CA raíz.
    """
    d1 = tmp_path / "ca1"
    d1.mkdir()
    pki1 = _reload_pki(monkeypatch, d1)
    _, pub_pem = _gen_user_pub_pem()
    cert_from_ca1 = pki1.pki_issue_user_cert("user@example.com", pub_pem)
    assert pki1.pki_verify_cert(cert_from_ca1) is True

    d2 = tmp_path / "ca2"
    d2.mkdir()
    pki2 = _reload_pki(monkeypatch, d2)
    pki2.pki_init_ca()
    pki2.pki_init_subca()
    assert pki2.pki_verify_cert(cert_from_ca1) is False


def test_pki_pub_from_cert_matches_input(tmp_path, monkeypatch):
    """Valida que la clave pública extraída del cert coincida con la original.

    Args:
        tmp_path (Path): Carpeta temporal para los artefactos de la PKI.
        monkeypatch (pytest.MonkeyPatch): Fixture para fijar el almacenamiento.

    Returns:
        None: Las aserciones comparan ambas claves en representación DER.
    """
    d = tmp_path / "ca"
    d.mkdir()
    pki = _reload_pki(monkeypatch, d)

    sk, pub_pem = _gen_user_pub_pem()
    cert_pem = pki.pki_issue_user_cert("user@example.com", pub_pem)

    extracted_pub_pem = pki.pki_pub_from_cert(cert_pem)
    orig = serialization.load_pem_public_key(pub_pem).public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    extr = serialization.load_pem_public_key(extracted_pub_pem).public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    assert orig == extr
