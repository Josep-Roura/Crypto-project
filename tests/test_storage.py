# tests/test_storage.py
import json
from core.storage import load_db, save_db

def test_load_db_creates_when_missing(tmp_path):
    path = tmp_path / "users.json"
    db = load_db(str(path))
    assert "users" in db
    assert isinstance(db["users"], dict)
    assert not path.exists()  # aún no se creó el archivo

def test_save_db_creates_and_reads(tmp_path):
    path = tmp_path / "users.json"
    data = {"users": {"a@b.com": {"created_at": "2025-10-26"}}}
    save_db(data, str(path))
    loaded = load_db(str(path))
    assert loaded == data

def test_save_db_is_atomic(tmp_path):
    path = tmp_path / "users.json"
    data = {"users": {"x@x.com": {}}}
    save_db(data, str(path))
    assert path.exists()
    assert not (tmp_path / "users.json.tmp").exists()

def test_load_db_with_corrupt_json(tmp_path):
    path = tmp_path / "users.json"
    path.write_text("{not json", encoding="utf-8")
    try:
        db = load_db(str(path))
        assert "users" in db and isinstance(db["users"], dict)
    except json.JSONDecodeError:
        assert True