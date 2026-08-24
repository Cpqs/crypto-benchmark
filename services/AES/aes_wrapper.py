import hashlib
import os
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def hash256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def encrypt(data: bytes, key: bytes) -> tuple[bytes, float]:
    if len(key) != 32:
        raise ValueError("key must be 32 bytes")

    nonce = os.urandom(12)

    aes = AESGCM(key)

    start = time.perf_counter()

    encrypted = nonce + aes.encrypt(
        nonce,
        data,
        None
    )

    end = time.perf_counter()

    crypto_time_ms = (
        end - start
    ) * 1000

    return encrypted, crypto_time_ms


def decrypt(data: bytes, key: bytes) -> tuple[bytes, float]:
    if len(key) != 32:
        raise ValueError("key must be 32 bytes")

    if len(data) < 12:
        raise ValueError("encrypted data too short")

    nonce = data[:12]
    ciphertext = data[12:]

    aes = AESGCM(key)

    start = time.perf_counter()

    decrypted = aes.decrypt(
        nonce,
        ciphertext,
        None
    )

    end = time.perf_counter()

    decrypt_time_ms = (
        end - start
    ) * 1000

    return decrypted, decrypt_time_ms