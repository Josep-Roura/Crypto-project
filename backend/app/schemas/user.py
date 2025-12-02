import uuid
"""Schema público para exponer datos de usuario sin información sensible."""

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr


class UserBase(BaseModel):
    """Datos básicos de usuario retornados por la API."""

    id: uuid.UUID
    username: str
    email: EmailStr
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
