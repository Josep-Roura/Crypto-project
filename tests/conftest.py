import os
import sys

import pytest
from starlette.testclient import TestClient

# Ruta de este archivo
THIS_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(THIS_DIR)

# Añadimos backend/ al sys.path para poder hacer `import app`
BACKEND_PATH = os.path.join(PROJECT_ROOT, "backend")
if BACKEND_PATH not in sys.path:
    sys.path.insert(0, BACKEND_PATH)

from app.main import app  # noqa: E402


@pytest.fixture(scope="session")
def client() -> TestClient:
    """
    Cliente compartido de FastAPI para todos los tests.
    """
    return TestClient(app)
