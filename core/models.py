# models.pys
from pydantic import BaseModel

class AesGcmResult(BaseModel):
    ciphertext: bytes
    nonce: bytes
    tag: bytes
