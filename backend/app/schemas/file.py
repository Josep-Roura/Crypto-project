from datetime import datetime
from uuid import UUID

from pydantic import BaseModel


class FileOut(BaseModel):
    id: UUID
    owner_id: UUID
    filename: str
    encryption_algorithm: str
    key_encryption_algorithm: str
    # 👇 Importante: YA NO ENVIAMOS LA FIRMA EN BRUTO
    # signature: bytes | None = None
    signature_algorithm: str | None = None
    created_at: datetime

    class Config:
        from_attributes = True


class FileShareRequest(BaseModel):
    target_username: str


class SharedFileOut(BaseModel):
    share_id: UUID
    file_id: UUID
    filename: str
    owner_username: str
    encryption_algorithm: str
    key_encryption_algorithm: str
    has_signature: bool
    created_at: datetime

    class Config:
        from_attributes = True


class SharedByMeOut(BaseModel):
    share_id: UUID
    file_id: UUID
    filename: str
    recipient_username: str
    encryption_algorithm: str
    key_encryption_algorithm: str
    has_signature: bool
    created_at: datetime

    class Config:
        from_attributes = True
