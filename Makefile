# Nombre del entorno virtual
VENV = env
PYTHON = $(VENV)/bin/python
PIP = $(VENV)/bin/pip
STREAMLIT = $(VENV)/bin/streamlit

# Ruta al script principal de Streamlit
APP = app_streamlit/Home.py

# Detecta la raíz del proyecto
export PYTHONPATH := $(shell pwd)

# Crear entorno virtual
$(VENV)/bin/activate: requirements.txt
	python3 -m venv $(VENV)
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt

# Ejecutar la app
run: $(VENV)/bin/activate
	$(STREAMLIT) run $(APP)

# Ejecutar tests
test: $(VENV)/bin/activate
	$(PYTHON) -m pytest -v

# Limpiar
clean:
	rm -rf $(VENV) __pycache__ */__pycache__ .pytest_cache