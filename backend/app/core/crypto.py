"""
Cryptographic helpers for hybrid encryption, key protection, and PKI utilities.

Notes:
- User private keys are encrypted with a key derived from the stored password hash. For
  a production system you'd derive from a user-supplied secret or use an HSM.
- CA private keys are encrypted with a constant master secret for simplicity in this
  academic project; replace with a secure vault/HSM in real deployments.
"""

import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.x509.oid import NameOID

CA_MASTER_SECRET = "crypto-drive-ca-secret"


def generate_rsa_keypair(key_size: int = 3072) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    return private_key, private_key.public_key()


def serialize_public_key(public_key: rsa.RSAPublicKey) -> str:
    return (
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        .decode("utf-8")
        .strip()
    )


def _derive_symmetric_key(secret: str) -> bytes:
    salt = hashes.Hash(hashes.SHA256())
    salt.update(secret.encode("utf-8"))
    salt_bytes = salt.finalize()[:16]

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt_bytes,
        iterations=390000,
    )
    return kdf.derive(secret.encode("utf-8"))


def encrypt_private_key(private_key: rsa.RSAPrivateKey, password_hash: str) -> bytes:
    aes_key = _derive_symmetric_key(password_hash)
    iv = os.urandom(12)
    aesgcm = AESGCM(aes_key)
    encrypted = aesgcm.encrypt(
        iv,
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ),
        None,
    )
    return iv + encrypted


def decrypt_private_key(encrypted_private_key: bytes, password_hash: str) -> rsa.RSAPrivateKey:
    aes_key = _derive_symmetric_key(password_hash)
    iv, ciphertext = encrypted_private_key[:12], encrypted_private_key[12:]
    aesgcm = AESGCM(aes_key)
    private_key_pem = aesgcm.decrypt(iv, ciphertext, None)
    return load_pem_private_key(private_key_pem, password=None)


def encrypt_ca_private_key(private_key: rsa.RSAPrivateKey) -> bytes:
    """Encrypt CA private key using a project-level master secret (demo only)."""
    aes_key = _derive_symmetric_key(CA_MASTER_SECRET)
    iv = os.urandom(12)
    aesgcm = AESGCM(aes_key)
    encrypted = aesgcm.encrypt(
        iv,
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ),
        None,
    )
    return iv + encrypted


def decrypt_ca_private_key(encrypted_private_key: bytes) -> rsa.RSAPrivateKey:
    aes_key = _derive_symmetric_key(CA_MASTER_SECRET)
    iv, ciphertext = encrypted_private_key[:12], encrypted_private_key[12:]
    aesgcm = AESGCM(aes_key)
    private_key_pem = aesgcm.decrypt(iv, ciphertext, None)
    return load_pem_private_key(private_key_pem, password=None)


def encrypt_symmetric_key_with_public_key(symmetric_key: bytes, public_key_pem: str) -> bytes:
    public_key = load_pem_public_key(public_key_pem.encode("utf-8"))
    return public_key.encrypt(
        symmetric_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )


def decrypt_symmetric_key_with_private_key(encrypted_key: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
    return private_key.decrypt(
        encrypted_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )


def encrypt_file_bytes(plaintext: bytes) -> Tuple[bytes, bytes, bytes, bytes]:
    """Return ciphertext, symmetric_key, iv, auth_tag."""
    symmetric_key = AESGCM.generate_key(bit_length=256)
    iv = os.urandom(12)
    aesgcm = AESGCM(symmetric_key)
    ciphertext = aesgcm.encrypt(iv, plaintext, None)
    auth_tag = ciphertext[-16:]
    return ciphertext, symmetric_key, iv, auth_tag


def decrypt_file_bytes(ciphertext: bytes, symmetric_key: bytes, iv: bytes) -> bytes:
    aesgcm = AESGCM(symmetric_key)
    return aesgcm.decrypt(iv, ciphertext, None)


def generate_storage_path(base_dir: str = "storage") -> str:
    os.makedirs(base_dir, exist_ok=True)
    return os.path.join(base_dir, f"{uuid.uuid4()}.bin")


def sign_bytes(private_key: rsa.RSAPrivateKey, data: bytes) -> bytes:
    return private_key.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )


def verify_signature(public_key: rsa.RSAPublicKey, data: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False


def generate_self_signed_ca(name: str, key_size: int = 4096) -> Tuple[rsa.RSAPrivateKey, x509.Certificate]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .sign(private_key, hashes.SHA256())
    )
    return private_key, cert


def generate_issuing_ca(
    root_private_key: rsa.RSAPrivateKey, root_cert: x509.Certificate, name: str
) -> Tuple[rsa.RSAPrivateKey, x509.Certificate]:
    issuing_private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(root_cert.subject)
        .public_key(issuing_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(root_private_key, hashes.SHA256())
    )
    return issuing_private_key, cert


def issue_user_certificate(
    issuing_private_key: rsa.RSAPrivateKey, issuing_cert: x509.Certificate, user_public_key_pem: str, common_name: str
) -> x509.Certificate:
    public_key = load_pem_public_key(user_public_key_pem.encode("utf-8"))
    now = datetime.now(timezone.utc)
    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .issuer_name(issuing_cert.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    )
    return cert_builder.sign(issuing_private_key, hashes.SHA256())


def serialize_certificate(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8").strip()


def load_certificate(pem: str) -> x509.Certificate:
    return x509.load_pem_x509_certificate(pem.encode("utf-8"))
