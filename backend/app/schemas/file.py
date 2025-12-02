"""Schemas relacionados con intercambio de archivos cifrados."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class FileOut(BaseModel):
    """Respuesta pública al listar un archivo cifrado.

    Incluye los algoritmos usados (AES-GCM para `encryption_algorithm`, RSA-OAEP para
    `key_encryption_algorithm`) para que el cliente sepa cómo procesar el recurso.
    La firma se omite para no exponer datos binarios innecesarios, pero se indica el
    algoritmo si existe.
    """

    id: UUID
    owner_id: UUID
    filename: str
    encryption_algorithm: str
    key_encryption_algorithm: str
    signature_algorithm: str | None = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class FileShareRequest(BaseModel):
    """Payload para compartir un archivo con otro usuario.

    Entradas: username de destino. En la capa de servicios se cifra la llave AES con su
    clave pública antes de crear el registro `FileShare`.
    """

    target_username: str


class SharedFileOut(BaseModel):
    """Archivo que me han compartido, con metadatos de cifrado.

    Expone si el archivo tiene firma (`has_signature`) para que el cliente decida si
    debe verificarla. Los algoritmos indican cómo descifrar la llave y el contenido.
    """

    share_id: UUID
    file_id: UUID
    filename: str
    owner_username: str
    encryption_algorithm: str
    key_encryption_algorithm: str
    has_signature: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class SharedByMeOut(BaseModel):
    """Archivo que he compartido con otra persona.

    Reutiliza los mismos campos criptográficos para que el frontend muestre cómo se
    protege la llave simétrica al reenviarla.
    """

    share_id: UUID
    file_id: UUID
    filename: str
    recipient_username: str
    encryption_algorithm: str
    key_encryption_algorithm: str
    has_signature: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
