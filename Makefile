# ============================================================
#  Proyecto Crypto-Project · Backend FastAPI
# ============================================================

VENV = .venv
PYTHON = $(VENV)/bin/python
PIP = $(VENV)/bin/pip
PYTHON_BIN = python3.12

BACKEND_DIR = backend
APP_MODULE = app.main:app

# Detecta la raíz del proyecto para imports relativos
export PYTHONPATH := $(shell pwd)/$(BACKEND_DIR)

# === Crear entorno virtual ===
$(VENV)/bin/activate: requirements.txt
$(PYTHON_BIN) -m venv $(VENV)
$(PIP) install --upgrade pip
$(PIP) install -r requirements.txt
@echo "✅ Entorno virtual creado y dependencias instaladas."

# === Ejecutar la API FastAPI ===
run: $(VENV)/bin/activate
cd $(BACKEND_DIR) && $(PYTHON) -m uvicorn $(APP_MODULE) --reload --host 0.0.0.0 --port 8000

# === Ejecutar tests con pytest ===
test: $(VENV)/bin/activate
@echo "🧪 Ejecutando tests con pytest..."
$(PYTHON) -m pytest -v --maxfail=1 --disable-warnings
@echo "✅ Tests completados."

# === Analizar calidad de código con ruff ===
lint: $(VENV)/bin/activate
@echo "🔍 Analizando código con ruff..."
$(PYTHON) -m ruff check $(BACKEND_DIR)
@echo "✅ Análisis completado."

# === Limpiar el proyecto ===
clean:
rm -rf $(VENV) __pycache__ */__pycache__ .pytest_cache .mypy_cache
@echo "🧹 Proyecto limpio."
