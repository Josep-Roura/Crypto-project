# --------------------------------------------------------------
# File: crypto_kdf.py
# Description: Derivación de claves simétricas seguras mediante Argon2id.
# --------------------------------------------------------------
"""Funciones de derivación de claves para proteger secretos del usuario."""

from argon2.low_level import Type, hash_secret_raw


def derive_kek(
    passphrase: str,
    salt: bytes,
    *,
    t: int = 3,
    m: int = 64 * 1024,
    p: int = 1,
    outlen: int = 32,
) -> bytes:
    """Deriva una clave de cifrado (KEK) usando Argon2id.

    Args:
        passphrase (str): Passphrase de entrada del usuario.
        salt (bytes): Salt aleatoria asociada a la passphrase.
        t (int): Coste temporal en iteraciones Argon2id.
        m (int): Memoria en KiB consumida durante la derivación.
        p (int): Paralelismo configurado para Argon2id.
        outlen (int): Longitud en bytes de la clave resultante.

    Returns:
        bytes: Clave simétrica derivada lista para cifrar secretos.

    """

    return hash_secret_raw(
        passphrase.encode("utf-8"),
        salt,
        time_cost=t,
        memory_cost=m,
        parallelism=p,
        hash_len=outlen,
        type=Type.ID,
    )
