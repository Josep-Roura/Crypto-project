# tests/test_pki_api.py
import importlib
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization


def _reload_pki(monkeypatch, storage_dir: Path):
    """Fija STORAGE_PATH y recarga api.pki para que recalculen CA_* en import-time."""
    monkeypatch.setenv("STORAGE_PATH", str(storage_dir))
    import api.pki as pki  # import local
    return importlib.reload(pki)


def _gen_user_pub_pem():
    """Genera par Ed25519 y devuelve (priv, pub_pem_bytes)."""
    sk = ed25519.Ed25519PrivateKey.generate()
    pk = sk.public_key()
    pub_pem = pk.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return sk, pub_pem


def test_pki_chain_ok_ed25519(tmp_path, monkeypatch):
    # Directorio con su propia CA
    d1 = tmp_path / "ca1"
    d1.mkdir()
    pki = _reload_pki(monkeypatch, d1)

    # Generar clave pública de usuario y emitir cert
    _, pub_pem = _gen_user_pub_pem()
    cert_pem = pki.pki_issue_user_cert("user@example.com", pub_pem)

    # Verificar cadena Usuario <- SubCA <- Root
    assert pki.pki_verify_cert(cert_pem) is True


def test_pki_chain_fails_with_wrong_root(tmp_path, monkeypatch):
    # CA #1: emitir certificado
    d1 = tmp_path / "ca1"
    d1.mkdir()
    pki1 = _reload_pki(monkeypatch, d1)
    _, pub_pem = _gen_user_pub_pem()
    cert_from_ca1 = pki1.pki_issue_user_cert("user@example.com", pub_pem)
    assert pki1.pki_verify_cert(cert_from_ca1) is True  # sanity check

    # CA #2: raíz distinta → debe fallar la verificación del cert emitido por CA #1
    d2 = tmp_path / "ca2"
    d2.mkdir()
    pki2 = _reload_pki(monkeypatch, d2)
    # Inicializa nuevas CA y SubCA en d2
    pki2.pki_init_ca()
    pki2.pki_init_subca()
    assert pki2.pki_verify_cert(cert_from_ca1) is False


def test_pki_pub_from_cert_matches_input(tmp_path, monkeypatch):
    d = tmp_path / "ca"
    d.mkdir()
    pki = _reload_pki(monkeypatch, d)

    # Generar par usuario y emitir cert
    sk, pub_pem = _gen_user_pub_pem()
    cert_pem = pki.pki_issue_user_cert("user@example.com", pub_pem)

    # Extraer la pública del cert y comparar con la original
    extracted_pub_pem = pki.pki_pub_from_cert(cert_pem)

    # Normaliza (bytes) y compara contenido (pueden diferir en cabeceras si formateo cambia)
    # Cargamos ambas y comparamos su representación DER:
    orig = serialization.load_pem_public_key(pub_pem).public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    extr = serialization.load_pem_public_key(extracted_pub_pem).public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    assert orig == extr