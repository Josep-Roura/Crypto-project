"""Gestión de la conexión a la base de datos.

Aunque no ciframos aquí, este módulo es clave para proteger datos sensibles: las
claves privadas y blobs cifrados se persisten en Postgres a través de estas sesiones.
Usamos `NullPool` en desarrollo para evitar mantener conexiones abiertas.
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool  # para desarrollo, sin acumular conexiones

from app.core.config import get_settings

settings = get_settings()

# ⚠️ MUY IMPORTANTE: convertir PostgresDsn -> str
DATABASE_URL = str(settings.database_url)

engine = create_engine(
    DATABASE_URL,
    future=True,
    pool_pre_ping=True,
    poolclass=NullPool,  # no mantenemos conexiones abiertas en el pool
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)


def get_db():
    """Dependency de FastAPI que abre/cierra una sesión de BD por petición.

    Entradas: ninguna; FastAPI inyecta el generador en los endpoints.
    Salidas: `Session` conectada a Postgres para leer/escribir material cifrado sin
    dejar conexiones huérfanas.
    """

    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
