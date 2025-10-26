# api/pki.py
import os
from datetime import datetime, timedelta, UTC
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID

DATA_DIR = os.getenv("STORAGE_PATH", "./_data")
CA_DIR = os.path.join(DATA_DIR, "ca")
CA_KEY = os.path.join(CA_DIR, "ca_key.pem")
CA_CERT = os.path.join(CA_DIR, "ca_cert.pem")
SUBCA_KEY = os.path.join(CA_DIR, "subca_key.pem")
SUBCA_CERT = os.path.join(CA_DIR, "subca_cert.pem")


def _ensure_dir() -> None:
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
        .not_valid_before(datetime.now(UTC) - timedelta(minutes=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=3650))  # 10 años
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )
    ca_cert = builder.sign(private_key=ca_priv, algorithm=None)

    # Guardar clave y cert
    with open(CA_KEY, "wb") as f:
        f.write(
            ca_priv.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
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
    Emite un certificado X.509 para la clave pública del usuario (Ed25519),
    firmado por la AC subordinada (AC2).
    """
    pki_init_ca()
    pki_init_subca()

    # Cargar AC2
    with open(SUBCA_KEY, "rb") as f:
        sub_priv = serialization.load_pem_private_key(f.read(), password=None)
    with open(SUBCA_CERT, "rb") as f:
        sub_cert = x509.load_pem_x509_certificate(f.read())

    user_pub = serialization.load_pem_public_key(user_pub_pem)

    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, email)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(sub_cert.subject)
        .public_key(user_pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(minutes=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=days_valid))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.RFC822Name(email)]), critical=False)
    )
    user_cert = builder.sign(private_key=sub_priv, algorithm=None)  # Ed25519
    return user_cert.public_bytes(serialization.Encoding.PEM)


def pki_verify_cert(cert_pem: bytes) -> bool:
    """
    Verifica cadena Usuario -> SubCA -> Root:
      - Fechas del usuario/subCA/root
      - Firma de usuario con SubCA
      - Firma de SubCA con Root
      - Coincidencia issuer/subject
    """
    pki_init_ca()
    pki_init_subca()

    # Cargar certs
    with open(CA_CERT, "rb") as f:
        root_cert = x509.load_pem_x509_certificate(f.read())
    with open(SUBCA_CERT, "rb") as f:
        sub_cert = x509.load_pem_x509_certificate(f.read())

    user_cert = x509.load_pem_x509_certificate(cert_pem)

    # Fechas (timezone-aware) usando propiedades *_utc
    now = datetime.now(UTC)
    if not (user_cert.not_valid_before_utc <= now <= user_cert.not_valid_after_utc):
        return False
    if not (sub_cert.not_valid_before_utc <= now <= sub_cert.not_valid_after_utc):
        return False
    if not (root_cert.not_valid_before_utc <= now <= root_cert.not_valid_after_utc):
        return False

    # Firmas: user <- subCA, subCA <- root
    try:
        sub_cert.public_key().verify(user_cert.signature, user_cert.tbs_certificate_bytes)
        root_cert.public_key().verify(sub_cert.signature, sub_cert.tbs_certificate_bytes)
    except Exception:  # verificación fallida
        return False

    # Issuers esperados
    if user_cert.issuer != sub_cert.subject:
        return False
    if sub_cert.issuer != root_cert.subject:
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


def pki_init_subca(common_name: str = "CryptoDrive Intermediate CA") -> None:
    """
    Crea una AC subordinada Ed25519 si no existe. Firmada por la CA raíz.
    """
    _ensure_dir()
    # Necesitamos la raíz primero
    pki_init_ca()
    if os.path.exists(SUBCA_KEY) and os.path.exists(SUBCA_CERT):
        return

    root_priv, root_cert = _load_ca()

    sub_priv = ed25519.Ed25519PrivateKey.generate()
    sub_pub = sub_priv.public_key()

    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(root_cert.subject)
        .public_key(sub_pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(minutes=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=3650))  # 10 años
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
    )
    # Ed25519 → algorithm=None
    sub_cert = builder.sign(private_key=root_priv, algorithm=None)

    with open(SUBCA_KEY, "wb") as f:
        f.write(
            sub_priv.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
    with open(SUBCA_CERT, "wb") as f:
        f.write(sub_cert.public_bytes(serialization.Encoding.PEM))