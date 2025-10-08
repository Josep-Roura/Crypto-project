from core.crypto_sym import encrypt_aes_gcm

def test_encrypt_returns_struct():
    res = encrypt_aes_gcm(b"hello")
    assert len(res.nonce) == 12
    assert len(res.tag) == 16
    assert len(res.ciphertext) > 0
