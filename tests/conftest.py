# tests/conftest.py
import os
import importlib
import pytest

@pytest.fixture(autouse=True)
def _isolate_storage(tmp_path, monkeypatch):
    """
    Aísla el almacenamiento: fija STORAGE_PATH a un dir temporal
    y recarga core.auth para que recalculen USERS_PATH con el nuevo entorno.
    """
    data_dir = tmp_path / "_data"
    data_dir.mkdir()
    monkeypatch.setenv("STORAGE_PATH", str(data_dir))

    # Importa y recarga el módulo que lee STORAGE_PATH en import-time
    import core.auth as auth_module  # import aquí, no arriba del archivo
    importlib.reload(auth_module)

    yield
    # tmp_path se limpia automáticamente