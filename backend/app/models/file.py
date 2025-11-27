import uuid
from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, LargeBinary, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.db.base import Base


class EncryptedFile(Base):
    __tablename__ = "files"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    owner_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    filename = Column(String(255), nullable=False)
    storage_path = Column(Text, nullable=False)
    encryption_algorithm = Column(String(100), nullable=False)
    iv = Column(LargeBinary, nullable=False)
    auth_tag = Column(LargeBinary, nullable=True)
    encrypted_key = Column(LargeBinary, nullable=False)
    key_encryption_algorithm = Column(String(100), nullable=False)
    signature = Column(LargeBinary, nullable=True)
    signature_algorithm = Column(String(100), nullable=True)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)

    owner = relationship("User", back_populates="files")
    shares = relationship("FileShare", back_populates="file", cascade="all, delete")
