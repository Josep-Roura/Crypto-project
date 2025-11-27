import uuid
from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.db.base import Base


class UserCert(Base):
    __tablename__ = "user_certs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    user_key_id = Column(UUID(as_uuid=True), ForeignKey("user_keys.id", ondelete="CASCADE"), nullable=False)
    ca_cert_id = Column(UUID(as_uuid=True), ForeignKey("ca_certs.id", ondelete="CASCADE"), nullable=False)
    cert_pem = Column(Text, nullable=False)
    revoked = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)

    user = relationship("User", back_populates="certificates")
    user_key = relationship("UserKey", back_populates="certificate")
    ca_cert = relationship("CACert", back_populates="issued_certs")
