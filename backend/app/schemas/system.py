"""Schemas de diagnóstico del sistema (health check)."""

from pydantic import BaseModel


class HealthOut(BaseModel):
    """Salida del endpoint /health con estado general y de la BD."""

    status: str
    db_ok: bool
