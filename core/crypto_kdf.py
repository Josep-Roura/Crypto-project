from argon2.low_level import hash_secret_raw, Type

def derive_kek(
    passphrase: str,
    salt: bytes,
    *,
    t: int = 3,
    m: int = 64 * 1024,  # 64 MiB para dev; en prod puedes subir a 256*1024
    p: int = 1,
    outlen: int = 32,
) -> bytes:
    """
    Deriva KEK (Key Encryption Key) con Argon2id.
    m es en KiB (64*1024 = 64 MiB). outlen en bytes (32 => 256 bits).
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
