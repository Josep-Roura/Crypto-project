import hashlib, hmac
from cipherlab.core.config import APP_SECRET

def derive_app_key(purpose: str, length: int = 32) -> bytes:
    # Deriva una clave a partir del secreto de la app (simple y suficiente para MVP)
    digest = hmac.new(APP_SECRET, purpose.encode(), hashlib.sha256).digest()
    if length <= len(digest):
        return digest[:length]
    out = b""
    counter = 1
    t = b""
    while len(out) < length:
        t = hmac.new(APP_SECRET, t + purpose.encode() + bytes([counter]), hashlib.sha256).digest()
        out += t
        counter += 1
    return out[:length]
