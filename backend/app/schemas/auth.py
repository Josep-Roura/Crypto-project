"""Schemas de autenticación para validar payloads de entrada/salida."""

import uuid
from datetime import datetime

from pydantic import BaseModel, EmailStr, Field


class UserCreate(BaseModel):
    """Datos necesarios para registrar un usuario.

    Entradas: username, email y contraseña en claro (min 6 caracteres). La contraseña se
    hashea con PBKDF2 en el backend antes de persistirla.
    Salidas: objeto validado que llega a la capa de servicios.
    """

    username: str = Field(..., min_length=3, max_length=150)
    email: EmailStr
    password: str = Field(..., min_length=6)


class UserLogin(BaseModel):
    """Credenciales básicas para iniciar sesión.

    Entradas: username y contraseña en claro.
    Salidas: objeto validado usado por la lógica de autenticación para comparar contra
    el hash guardado.
    """

    username: str
    password: str


class UserOut(BaseModel):
    """Representación pública de un usuario autenticado.

    Excluimos hashes y material sensible; solo enviamos identificadores y timestamps
    para evitar fugas.
    """

    id: uuid.UUID
    username: str
    email: EmailStr
    created_at: datetime

    class Config:
        orm_mode = True
