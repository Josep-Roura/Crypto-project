# ============================================================
#  Proyecto Crypto-Project  ·  Gestión de claves y cifrado
# ============================================================

# === Entorno virtual y comandos base ===
# === Entorno virtual y comandos base ===
VENV = .venv
PYTHON = $(VENV)/bin/python
PIP = $(VENV)/bin/pip
STREAMLIT = $(VENV)/bin/streamlit
PYLINT = $(VENV)/bin/pylint
PYTHON_BIN = python3.12


# === Rutas principales ===
APP = app_streamlit/Home.py
SRC = core
TESTS = tests
PYLINT = $(VENV)/bin/pylint

# Detecta la raíz del proyecto para imports relativos
export PYTHONPATH := $(shell pwd)

# === Crear entorno virtual ===
$(VENV)/bin/activate: requirements.txt
	$(PYTHON_BIN) -m venv $(VENV)
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt
	@echo "✅ Entorno virtual creado y dependencias instaladas."

# === Ejecutar la app Streamlit ===
run: $(VENV)/bin/activate
	$(STREAMLIT) run $(APP)

# === Ejecutar tests con pytest ===
test: $(VENV)/bin/activate
	@echo "🧪 Ejecutando tests con pytest..."
	$(PYTHON) -m pytest -v --maxfail=1 --disable-warnings
	@echo "✅ Tests completados."

# === Analizar calidad de código con pylint ===
lint: $(VENV)/bin/activate
	@echo "🔍 Analizando código con pylint..."
	$(PYLINT) $(SRC)
	@echo "✅ Análisis completado."

# === QA: combina lint + tests ===
qa: $(VENV)/bin/activate
	@echo "🚀 Iniciando control de calidad completo (lint + tests)..."
	@make lint
	@make test
	@echo "🎯 Control de calidad finalizado sin errores."

# === Limpiar el proyecto ===
clean:
	rm -rf $(VENV) __pycache__ */__pycache__ .pytest_cache .mypy_cache
	@echo "🧹 Proyecto limpio."