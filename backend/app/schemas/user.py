import uuid
"""Schema público para exponer datos de usuario sin información sensible."""

import uuid
from datetime import datetime

from pydantic import BaseModel, EmailStr


class UserBase(BaseModel):
    """Datos básicos de usuario retornados por la API."""

    id: uuid.UUID
    username: str
    email: EmailStr
    created_at: datetime

    class Config:
        orm_mode = True
