# api/pki.py
import os, datetime as dt
from typing import Optional
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID

DATA_DIR = os.getenv("STORAGE_PATH", "./_data")
CA_DIR = os.path.join(DATA_DIR, "ca")
CA_KEY = os.path.join(CA_DIR, "ca_key.pem")
CA_CERT = os.path.join(CA_DIR, "ca_cert.pem")

def _ensure_dir():
    os.makedirs(CA_DIR, exist_ok=True)

def pki_init_ca(common_name: str = "CryptoDrive Local CA") -> None:
    """
    Crea una CA Ed25519 si no existe. Guarda ca_key.pem y ca_cert.pem en _data/ca/.
    """
    _ensure_dir()
    if os.path.exists(CA_KEY) and os.path.exists(CA_CERT):
        return

    # Generar clave privada de la CA
    ca_priv = ed25519.Ed25519PrivateKey.generate()
    ca_pub = ca_priv.public_key()

    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(ca_pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(dt.datetime.utcnow() - dt.timedelta(minutes=1))
        .not_valid_after(dt.datetime.utcnow() + dt.timedelta(days=3650))  # 10 años
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False,
        ), critical=True)
    )
    ca_cert = builder.sign(private_key=ca_priv, algorithm=None)

    # Guardar clave y cert
    with open(CA_KEY, "wb") as f:
        f.write(ca_priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
    with open(CA_CERT, "wb") as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))

def _load_ca():
    with open(CA_KEY, "rb") as f:
        ca_priv = serialization.load_pem_private_key(f.read(), password=None)
    with open(CA_CERT, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    return ca_priv, ca_cert

def pki_issue_user_cert(email: str, user_pub_pem: bytes, days_valid: int = 365) -> bytes:
    """
    Emite un certificado X.509 para la clave pública Ed25519 del usuario con CN=email.
    Devuelve cert PEM (bytes).
    """
    pki_init_ca()
    ca_priv, ca_cert = _load_ca()

    user_pub = serialization.load_pem_public_key(user_pub_pem)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, email)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(user_pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(dt.datetime.utcnow() - dt.timedelta(minutes=1))
        .not_valid_after(dt.datetime.utcnow() + dt.timedelta(days=days_valid))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=True,
            key_encipherment=False, data_encipherment=False,
            key_agreement=False, key_cert_sign=False, crl_sign=False,
            encipher_only=False, decipher_only=False
        ), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.RFC822Name(email)]), critical=False)
    )
    user_cert = builder.sign(private_key=ca_priv, algorithm=None)
    return user_cert.public_bytes(serialization.Encoding.PEM)

def pki_verify_cert(cert_pem: bytes) -> bool:
    """
    Verifica firma del certificado con la CA local y fechas de validez.
    """
    pki_init_ca()
    _, ca_cert = _load_ca()
    user_cert = x509.load_pem_x509_certificate(cert_pem)

    # 1) Fechas
    now = dt.datetime.utcnow()
    if not (user_cert.not_valid_before <= now <= user_cert.not_valid_after):
        return False

    # 2) Firma de la CA (self “chain” 1 salto)
    ca_pub = ca_cert.public_key()
    try:
        ca_pub.verify(user_cert.signature, user_cert.tbs_certificate_bytes)
    except Exception:
        return False

    # 3) (Opcional) comprobar que issuer == ca subject
    if user_cert.issuer != ca_cert.subject:
        return False

    return True

def pki_pub_from_cert(cert_pem: bytes) -> bytes:
    """
    Extrae la public key PEM de un certificado X.509 Ed25519.
    """
    cert = x509.load_pem_x509_certificate(cert_pem)
    pub = cert.public_key()
    return pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )