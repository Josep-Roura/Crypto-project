# Crypto Drive (MVP A1)

## Requisitos
- Python 3.11+
- (Opcional) Docker

## Setup
```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
ruff check .
pytest -q
streamlit run app_streamlit/Home.py
