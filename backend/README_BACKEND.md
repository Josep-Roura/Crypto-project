# Backend FastAPI

Punto de entrada: `app/main.py`. Incluye routers para salud y autenticación, conexión a PostgreSQL mediante SQLAlchemy y configuración por variables de entorno.

## Ejecución local
1. Crear el entorno virtual: `python -m venv .venv` y activarlo.
2. Instalar dependencias: `pip install -r requirements.txt`.
3. Copiar el archivo de ejemplo: `cp .env.example .env` y ajustar `DATABASE_URL` y `APP_NAME`.
4. Lanzar el servidor: `uvicorn app.main:app --reload`.

## Estructura
- `app/core`: configuración y utilidades (incluye hashing de contraseñas).
- `app/db`: conexión y sesión de base de datos.
- `app/models`: modelos SQLAlchemy para usuarios y ficheros cifrados.
- `app/api`: rutas REST (salud y autenticación).
- `app/schemas`: modelos Pydantic para peticiones y respuestas.

La lógica criptográfica (cifrado híbrido, PKI y compartición segura de ficheros) ya está implementada sobre esta base.

## PKI y certificados
- `POST /api/pki/bootstrap`: inicializa la infraestructura PKI creando una CA raíz y una CA emisora y guardando ambas en la tabla `ca_certs`.
- `POST /api/pki/cert/me`: emite un certificado X.509 para el usuario autenticado a partir de su clave pública almacenada en `user_keys`, firmado por la CA emisora.
- `GET /api/pki/cert/me`: devuelve el certificado del usuario (`user_cert_pem`) y la cadena de confianza (Root + Issuing).

Para este proyecto demo, el backend identifica al usuario en las rutas protegidas mediante el header `X-User-Id` que contiene el UUID del usuario.
