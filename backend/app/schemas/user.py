import uuid
from datetime import datetime

from pydantic import BaseModel, EmailStr


class UserBase(BaseModel):
    id: uuid.UUID
    username: str
    email: EmailStr
    created_at: datetime

    class Config:
        orm_mode = True
