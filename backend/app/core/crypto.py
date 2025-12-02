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
    """Crea un par RSA (privada/pública) usando exponente 65537.

    Algoritmo: RSA con un tamaño de clave configurable (por defecto 3072 bits) generado
    con la implementación de `cryptography`.
    Entradas: tamaño de la clave en bits.
    Salidas: clave privada y clave pública asociada listas para ser serializadas o usadas
    en operaciones de firma y cifrado asimétrico.
    """

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    return private_key, private_key.public_key()


def serialize_public_key(public_key: rsa.RSAPublicKey) -> str:
    """Convierte la clave pública RSA a texto PEM para almacenarla o exponerla.

    Algoritmo: codificación PEM usando el formato `SubjectPublicKeyInfo`.
    Entradas: objeto de clave pública RSA.
    Salidas: cadena en PEM sin espacios extra que puede guardarse en la base de datos o
    enviarse por la API.
    """

    return (
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        .decode("utf-8")
        .strip()
    )


def _derive_symmetric_key(secret: str) -> bytes:
    """Deriva una llave simétrica a partir de un secreto mediante PBKDF2-HMAC-SHA256.

    Algoritmo: PBKDF2 con SHA-256, 390k iteraciones y una sal fija derivada del propio
    secreto. Aunque es aceptable para pruebas, en producción conviene una sal aleatoria
    y almacenada aparte.
    Entradas: secreto en texto plano (normalmente el hash de la contraseña o un secreto
    maestro).
    Salidas: llave de 32 bytes adecuada para AES-256-GCM.
    """

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
    """Protege una clave privada con AES-256-GCM derivando la llave desde el password hash.

    Algoritmo: AES-GCM con IV aleatorio de 96 bits; la llave sale de PBKDF2-HMAC-SHA256
    tomando como entrada el hash de la contraseña del usuario.
    Entradas: clave privada RSA y hash de contraseña asociado al usuario.
    Salidas: blob binario que concatena el IV y el texto cifrado listo para persistir.
    """

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
    """Recupera una clave privada RSA cifrada con AES-256-GCM.

    Algoritmo: AES-GCM usando la llave derivada del hash de contraseña. Espera que el
    blob de entrada comience con el IV de 12 bytes seguido del ciphertext generado por
    `encrypt_private_key`.
    Entradas: bytes con IV + ciphertext y el hash de la contraseña correspondiente.
    Salidas: objeto de clave privada listo para firmar o descifrar.
    """

    aes_key = _derive_symmetric_key(password_hash)
    iv, ciphertext = encrypted_private_key[:12], encrypted_private_key[12:]
    aesgcm = AESGCM(aes_key)
    private_key_pem = aesgcm.decrypt(iv, ciphertext, None)
    return load_pem_private_key(private_key_pem, password=None)


def encrypt_ca_private_key(private_key: rsa.RSAPrivateKey) -> bytes:
    """Cifra la clave privada de la CA con AES-256-GCM y el secreto maestro del proyecto.

    Algoritmo: AES-GCM con IV aleatorio de 96 bits; la llave se deriva del string
    constante `CA_MASTER_SECRET`, útil solo para entorno académico.
    Entradas: clave privada RSA de la CA raíz o issuing.
    Salidas: blob con IV + ciphertext que puede almacenarse en base de datos.
    """
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
    """Descifra la clave privada de la CA usando el secreto maestro del proyecto.

    Algoritmo: AES-256-GCM con llave derivada de `CA_MASTER_SECRET`. Se asume el mismo
    formato IV + ciphertext que `encrypt_ca_private_key`.
    Entradas: bytes cifrados almacenados en base de datos.
    Salidas: clave privada RSA de la CA lista para emitir certificados.
    """

    aes_key = _derive_symmetric_key(CA_MASTER_SECRET)
    iv, ciphertext = encrypted_private_key[:12], encrypted_private_key[12:]
    aesgcm = AESGCM(aes_key)
    private_key_pem = aesgcm.decrypt(iv, ciphertext, None)
    return load_pem_private_key(private_key_pem, password=None)


def encrypt_symmetric_key_with_public_key(symmetric_key: bytes, public_key_pem: str) -> bytes:
    """Cifra una llave simétrica con la clave pública RSA del destinatario.

    Algoritmo: RSA-OAEP con SHA-256 tanto para el hash principal como para MGF1.
    Entradas: llave simétrica cruda (bytes) y la clave pública en PEM del receptor.
    Salidas: ciphertext asimétrico listo para almacenarse junto al archivo cifrado.
    """

    public_key = load_pem_public_key(public_key_pem.encode("utf-8"))
    return public_key.encrypt(
        symmetric_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )


def decrypt_symmetric_key_with_private_key(encrypted_key: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
    """Descifra una llave simétrica protegida con RSA-OAEP.

    Algoritmo: RSA-OAEP con SHA-256. Se usa la clave privada correspondiente a la
    pública que protegió el secreto.
    Entradas: ciphertext del secreto simétrico y la clave privada RSA.
    Salidas: llave simétrica en claro lista para usar con AES-GCM.
    """

    return private_key.decrypt(
        encrypted_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )


def encrypt_file_bytes(plaintext: bytes) -> Tuple[bytes, bytes, bytes, bytes]:
    """Cifra el contenido de un archivo con AES-256-GCM.

    Algoritmo: AES-GCM con IV aleatorio de 96 bits. La etiqueta de autenticación queda
    incluida al final del ciphertext según el comportamiento de AESGCM.
    Entradas: bytes del archivo en claro.
    Salidas: ciphertext completo, llave simétrica generada, IV y etiqueta de
    autenticación para verificar integridad.
    """

    symmetric_key = AESGCM.generate_key(bit_length=256)
    iv = os.urandom(12)
    aesgcm = AESGCM(symmetric_key)
    ciphertext = aesgcm.encrypt(iv, plaintext, None)
    auth_tag = ciphertext[-16:]
    return ciphertext, symmetric_key, iv, auth_tag


def decrypt_file_bytes(ciphertext: bytes, symmetric_key: bytes, iv: bytes) -> bytes:
    """Devuelve el archivo en claro usando AES-256-GCM.

    Algoritmo: AES-GCM reutilizando el IV de 96 bits y la llave simétrica con la que se
    cifró. La autenticación se valida de forma implícita; si falla, se lanzará
    excepción.
    Entradas: ciphertext completo, llave simétrica y IV.
    Salidas: bytes originales del archivo.
    """

    aesgcm = AESGCM(symmetric_key)
    return aesgcm.decrypt(iv, ciphertext, None)


def generate_storage_path(base_dir: str = "storage") -> str:
    """Genera una ruta única para guardar blobs cifrados en disco.

    Algoritmo: usa `uuid4` para evitar colisiones y crea el directorio si no existe.
    Entradas: nombre del directorio base (por defecto `storage`).
    Salidas: ruta completa donde escribir el ciphertext del archivo.
    """

    os.makedirs(base_dir, exist_ok=True)
    return os.path.join(base_dir, f"{uuid.uuid4()}.bin")


def sign_bytes(private_key: rsa.RSAPrivateKey, data: bytes) -> bytes:
    """Firma datos arbitrarios con RSA-PSS usando SHA-256.

    Algoritmo: RSA-PSS con sal máxima y MGF1+SHA-256, hash principal SHA-256.
    Entradas: clave privada RSA y datos a firmar en bytes.
    Salidas: firma binaria que puede verificarse con la clave pública correspondiente.
    """

    return private_key.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )


def verify_signature(public_key: rsa.RSAPublicKey, data: bytes, signature: bytes) -> bool:
    """Valida una firma RSA-PSS-SHA256 y devuelve un booleano sencillo.

    Algoritmo: RSA-PSS con los mismos parámetros que `sign_bytes`. Cualquier excepción
    durante la verificación se transforma en `False` para simplificar el manejo de
    errores en la API.
    Entradas: clave pública RSA, datos originales y firma recibida.
    Salidas: `True` si la firma es válida, `False` en caso contrario.
    """

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
    """Crea una CA raíz autofirmada para el proyecto.

    Algoritmo: par RSA de 4096 bits y certificado X.509 autofirmado con SHA-256. El
    certificado permite firmar a otra CA (path_length=1).
    Entradas: nombre común (CN) y tamaño de la clave.
    Salidas: clave privada de la CA y certificado en memoria listo para serializar.
    """

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
    """Genera una CA subordinada firmada por la raíz.

    Algoritmo: par RSA de 4096 bits y certificado X.509 firmado por la raíz usando
    SHA-256. Se limita el path_length a 0 para que solo pueda emitir usuarios.
    Entradas: clave privada y certificado de la raíz, más el CN para la nueva CA.
    Salidas: clave privada de la issuing CA y su certificado firmado.
    """

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
    """Emite un certificado de usuario con la CA subordinada.

    Algoritmo: certificado X.509 firmado con SHA-256 usando la clave privada de la
    issuing CA. No permite delegación (BasicConstraints ca=False).
    Entradas: clave privada de la issuing CA, su certificado, la clave pública del
    usuario en PEM y el Common Name deseado.
    Salidas: certificado X.509 del usuario en memoria.
    """

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
    """Convierte un certificado X.509 en PEM para almacenarlo o entregarlo por API."""
    return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8").strip()


def load_certificate(pem: str) -> x509.Certificate:
    """Carga un certificado X.509 en memoria a partir de su representación PEM."""
    return x509.load_pem_x509_certificate(pem.encode("utf-8"))
