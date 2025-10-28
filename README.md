# Crypto Drive (MVP A1)

## Descripción general
Crypto Drive es un servicio mínimo para gestionar identidades y almacenamiento cifrado. El
sistema permite derivar secretos a partir de credenciales de usuario, proteger claves privadas
mediante AES-GCM y firmar manifiestos con Ed25519 respaldados por una jerarquía PKI local.

## Componentes principales
- `core/`: Implementaciones criptográficas base (KDF, cifrado simétrico, firmas y modelos de
  dominio) junto con políticas de contraseñas y almacenamiento local.
- `api/`: Servicios de alto nivel que coordinan la gestión de certificados, la emisión de firmas y
  la persistencia de usuarios en JSON.
- `app_streamlit/`: Interfaz ligera en Streamlit para interactuar con las operaciones más
  relevantes del sistema.
- `infra/`: Scripts y utilidades de despliegue o aprovisionamiento.
- `tests/`: Casos automatizados que cubren la lógica crítica del dominio.

## Flujo criptográfico
1. La contraseña del usuario se deriva con `core.crypto_kdf` para obtener un secreto seguro.
2. Las claves Ed25519 se generan mediante `core.crypto_sign` y se almacenan cifradas con
   AES-GCM usando el secreto derivado.
3. El módulo `api.pki` crea una CA raíz y una subordinada locales para emitir certificados X.509
   vinculados a cada clave pública.
4. `api.services.sign_manifest` crea huellas deterministas de un manifiesto, firma el digest y
   adjunta el certificado del usuario para permitir validación posterior.

## Requisitos
- Python 3.11+
- (Opcional) Docker para aislar la ejecución.

## Instalación y uso
```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\\Scripts\\activate
pip install -r requirements.txt
```

### Ejecución de comprobaciones
```bash
ruff check .
pytest -q
```

### Interfaz Streamlit
```bash
streamlit run app_streamlit/Home.py
```

## Variables de entorno relevantes
- `STORAGE_PATH`: Directorio donde se almacenan usuarios, claves y certificados. Por defecto
  utiliza `./_data`.

## Estructura de almacenamiento
- `_data/users.json`: Base de datos de usuarios persistida en formato JSON.
- `_data/ca/`: Carpeta que guarda claves y certificados de la autoridad raíz y subordinada.
