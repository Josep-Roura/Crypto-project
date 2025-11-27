import uuid
from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, LargeBinary, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.db.base import Base


class CACert(Base):
    __tablename__ = "ca_certs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String, nullable=False)
    cert_pem = Column(Text, nullable=False)
    private_key_encrypted = Column(LargeBinary, nullable=False)
    is_root = Column(Boolean, nullable=False, default=False)
    parent_id = Column(UUID(as_uuid=True), ForeignKey("ca_certs.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)

    parent = relationship("CACert", remote_side=[id])
    issued_certs = relationship("UserCert", back_populates="ca_cert", cascade="all, delete")
