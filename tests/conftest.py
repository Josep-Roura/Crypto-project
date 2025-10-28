# --------------------------------------------------------------
# File: conftest.py
# Description: Fixtures compartidas para aislar almacenamiento y recargar módulos.
# --------------------------------------------------------------

import importlib
from typing import Iterator

import pytest


@pytest.fixture(autouse=True)
def _isolate_storage(tmp_path, monkeypatch) -> Iterator[None]:
    """Aísla STORAGE_PATH y recarga core.auth para cada prueba.

    Args:
        tmp_path (Path): Carpeta temporal proporcionada por pytest.
        monkeypatch (pytest.MonkeyPatch): Fixture para ajustar variables de entorno.

    Returns:
        Iterator[None]: Control del fixture autouse durante la ejecución de cada test.
    """
    data_dir = tmp_path / "_data"
    data_dir.mkdir()
    monkeypatch.setenv("STORAGE_PATH", str(data_dir))

    import core.auth as auth_module

    importlib.reload(auth_module)

    yield
    # tmp_path se limpia automáticamente por pytest
