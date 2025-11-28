# tests/conftest.py

import os
import sys
from pathlib import Path

import pytest
from starlette.testclient import TestClient

# === Localizar rutas del proyecto ===
THIS_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = THIS_DIR.parent  # C:\Users\...\Crypto-project
BACKEND_PATH = PROJECT_ROOT / "backend"

# Añadimos backend/ al sys.path para que funcione "from app.main import app"
if str(BACKEND_PATH) not in sys.path:
    sys.path.insert(0, str(BACKEND_PATH))

# === Cargar variables de entorno desde backend/.env ANTES de importar app ===
env_file = BACKEND_PATH / ".env"

if env_file.exists():
    with env_file.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            # Saltar comentarios y líneas vacías
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            # No machacamos si ya está definido fuera
            os.environ.setdefault(key, value)
else:
    # Fallback por si alguien ejecuta los tests sin .env.
    # Ajusta esto solo si quieres testear con otra DB.
    os.environ.setdefault(
        "DATABASE_URL",
        "postgresql+psycopg://postgres:postgres@localhost:5432/postgres",
    )
    os.environ.setdefault("JWT_SECRET_KEY", "testsecret")

# Importamos la app ya con las variables preparadas
from app.main import app  # noqa: E402


@pytest.fixture(scope="session")
def client() -> TestClient:
    """
    Cliente de pruebas compartido para toda la sesión de pytest.
    """
    return TestClient(app)
