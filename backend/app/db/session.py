# backend/app/db/session.py
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
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
