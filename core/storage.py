# core/storage.py
from __future__ import annotations

import json
import os
from typing import Any, Dict

__all__ = ["load_db", "save_db"]

_DEFAULT_DB: Dict[str, Any] = {"users": {}}


def _ensure_parent_dir(path: str) -> None:
    """Crea el directorio padre si no existe."""
    parent = os.path.dirname(path) or "."
    os.makedirs(parent, exist_ok=True)


def load_db(path: str) -> Dict[str, Any]:
    """
    Carga un JSON desde 'path'.
    - Si no existe, devuelve {'users': {}}.
    - Si está corrupto, devuelve también {'users': {}} (fail-safe).
      (Si prefieres propagar el error, cambia el except a 'raise').
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return dict(_DEFAULT_DB)
    except json.JSONDecodeError:
        return dict(_DEFAULT_DB)


def save_db(db: Dict[str, Any], path: str) -> None:
    """
    Guarda 'db' en JSON usando escritura atómica:
    escribe en 'path.tmp' y luego reemplaza el definitivo.
    """
    _ensure_parent_dir(path)
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(db, f, indent=2, ensure_ascii=False)
    os.replace(tmp, path)