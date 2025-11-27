from datetime import datetime
from uuid import UUID

from pydantic import BaseModel


class KeyStatus(BaseModel):
    has_keys: bool


class UserKeyOut(BaseModel):
    id: UUID
    user_id: UUID
    public_key_pem: str
    created_at: datetime

    class Config:
        from_attributes = True
