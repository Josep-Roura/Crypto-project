"""Declarative base de SQLAlchemy para los modelos del proyecto.

No hay lógica criptográfica aquí, pero todo lo que guardamos (claves, blobs cifrados,
certificados) se apoya en estas clases para mapearse a Postgres.
"""

from sqlalchemy.orm import declarative_base

Base = declarative_base()
