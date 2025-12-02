import uuid
from datetime import datetime

from sqlalchemy import Column, DateTime, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.db.base import Base


class User(Base):
    """Tabla de usuarios autenticados.

    Cada usuario guarda su hash de contraseña (PBKDF2) y sirve como dueño de claves
    RSA, certificados X.509 y archivos cifrados. Los timestamps permiten auditar
    altas y modificaciones.
    """

    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username = Column(String(150), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)

    files = relationship("EncryptedFile", back_populates="owner", cascade="all, delete")
    user_key = relationship("UserKey", uselist=False, back_populates="user", cascade="all, delete")
    certificates = relationship("UserCert", back_populates="user", cascade="all, delete")
