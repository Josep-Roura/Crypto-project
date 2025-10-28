# --------------------------------------------------------------
# File: storage.py
# Description: Utilidades de persistencia para la base de datos JSON de usuarios.
# --------------------------------------------------------------
"""Funciones auxiliares de entrada/salida para el almacenamiento local."""

from __future__ import annotations

import json
import os
from typing import Any, Dict

__all__ = ["load_db", "save_db"]

_DEFAULT_DB: Dict[str, Any] = {"users": {}}


def _ensure_parent_dir(path: str) -> None:
    """Garantiza que exista el directorio padre del archivo de destino."""

    parent = os.path.dirname(path) or "."
    os.makedirs(parent, exist_ok=True)


def load_db(path: str) -> Dict[str, Any]:
    """Carga un archivo JSON y devuelve un diccionario seguro para uso interno.

    Args:
        path (str): Ruta del archivo JSON de usuarios.

    Returns:
        Dict[str, Any]: Estructura cargada o la base vacía si no es accesible.

    """

    try:
        with open(path, "r", encoding="utf-8") as handler:
            return json.load(handler)
    except (FileNotFoundError, json.JSONDecodeError):
        return dict(_DEFAULT_DB)


def save_db(db: Dict[str, Any], path: str) -> None:
    """Guarda la base de datos JSON aplicando escritura atómica."""

    _ensure_parent_dir(path)
    tmp_path = f"{path}.tmp"
    with open(tmp_path, "w", encoding="utf-8") as handler:
        json.dump(db, handler, indent=2, ensure_ascii=False)
    os.replace(tmp_path, path)