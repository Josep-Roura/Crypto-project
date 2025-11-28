# tests/conftest.py
import os
import sys

import pytest
from starlette.testclient import TestClient

# Compute project root: .../Crypto-project
THIS_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(THIS_DIR)

# Add backend/ to sys.path so that `import app` works
BACKEND_PATH = os.path.join(PROJECT_ROOT, "backend")
if BACKEND_PATH not in sys.path:
    sys.path.insert(0, BACKEND_PATH)

from app.main import app  # noqa: E402


@pytest.fixture(scope="session")
def client() -> TestClient:
    """
    Shared FastAPI TestClient for the whole test session.
    """
    return TestClient(app)
