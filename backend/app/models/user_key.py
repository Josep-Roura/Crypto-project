import uuid
from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, LargeBinary, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.db.base import Base


class UserKey(Base):
    __tablename__ = "user_keys"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), unique=True, nullable=False)
    public_key_pem = Column(String, nullable=False)
    private_key_encrypted = Column(LargeBinary, nullable=False)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)

    user = relationship("User", back_populates="user_key")
    certificate = relationship("UserCert", uselist=False, back_populates="user_key", cascade="all, delete")
