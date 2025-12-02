"""Schemas relacionados con la gestión de claves RSA de los usuarios."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class KeyStatus(BaseModel):
    """Indica si el usuario ya generó su par RSA."""

    has_keys: bool


class UserKeyOut(BaseModel):
    """Respuesta con la clave pública protegida."""

    id: UUID
    user_id: UUID
    public_key_pem: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
