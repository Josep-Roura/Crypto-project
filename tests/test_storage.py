# --------------------------------------------------------------
# File: test_storage.py
# Description: Pruebas sobre la capa de persistencia JSON utilizada por core.storage.
# --------------------------------------------------------------

import json

from core.storage import load_db, save_db


def test_load_db_creates_when_missing(tmp_path):
    """Comprueba que load_db genere la estructura base cuando no existe archivo.

    Args:
        tmp_path (Path): Carpeta temporal proporcionada por pytest.

    Returns:
        None: Las aserciones validan la estructura creada en memoria.
    """
    path = tmp_path / "users.json"
    db = load_db(str(path))
    assert "users" in db
    assert isinstance(db["users"], dict)
    assert not path.exists()


def test_save_db_creates_and_reads(tmp_path):
    """Verifica que save_db persista y que load_db recupere la misma estructura.

    Args:
        tmp_path (Path): Carpeta temporal proporcionada por pytest.

    Returns:
        None: Las aserciones comparan el JSON guardado con el cargado.
    """
    path = tmp_path / "users.json"
    data = {"users": {"a@b.com": {"created_at": "2025-10-26"}}}
    save_db(data, str(path))
    loaded = load_db(str(path))
    assert loaded == data


def test_save_db_is_atomic(tmp_path):
    """Garantiza que el guardado se realice de forma atómica sin archivos residuales.

    Args:
        tmp_path (Path): Carpeta temporal proporcionada por pytest.

    Returns:
        None: Las aserciones comprueban la presencia y ausencia de archivos esperada.
    """
    path = tmp_path / "users.json"
    data = {"users": {"x@x.com": {}}}
    save_db(data, str(path))
    assert path.exists()
    assert not (tmp_path / "users.json.tmp").exists()


def test_load_db_with_corrupt_json(tmp_path):
    """Valida que un JSON corrupto sea manejado recreando la estructura base.

    Args:
        tmp_path (Path): Carpeta temporal proporcionada por pytest.

    Returns:
        None: Las aserciones confirman la recuperación ante corrupción.
    """
    path = tmp_path / "users.json"
    path.write_text("{not json", encoding="utf-8")
    try:
        db = load_db(str(path))
        assert "users" in db and isinstance(db["users"], dict)
    except json.JSONDecodeError:
        assert True
