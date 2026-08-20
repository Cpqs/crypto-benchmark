import atexit
import concurrent.futures
import threading
import time

_crypto_pool = None
_pool_lock = threading.Lock()


def _get_pool():
    global _crypto_pool

    if _crypto_pool is None:
        with _pool_lock:
            if _crypto_pool is None:
                _crypto_pool = concurrent.futures.ProcessPoolExecutor(
                    max_workers=1
                )
                atexit.register(_shutdown_pool)

    return _crypto_pool


def _shutdown_pool():
    global _crypto_pool

    if _crypto_pool is not None:
        _crypto_pool.shutdown(wait=True)
        _crypto_pool = None


def _to_octet(bee2_lib, data: bytes):
    """Копирует Python bytes в память, которой управляет bee2."""
    vp = bee2_lib.memAlloc(len(data))

    if data:
        bee2_lib.memmove(vp, data)

    op = bee2_lib.vp2op(vp)

    return vp, op


def _worker_hash256(data: bytes) -> bytes:
    from . import bee2_lib

    if not data:
        return b"\x00" * 32

    data_vp, _ = _to_octet(bee2_lib, data)
    hash_vp = bee2_lib.memAlloc(32)
    hash_op = bee2_lib.vp2op(hash_vp)

    try:
        err = bee2_lib.bashHash(
            hash_op,
            256,
            data_vp,
            len(data),
        )

        if err != 0:
            raise RuntimeError(f"bashHash error: {err}")

        return bytes(bee2_lib.cdata(hash_vp, 32))

    finally:
        bee2_lib.memFree(data_vp)
        bee2_lib.memFree(hash_vp)


def _worker_encrypt(data: bytes, key: bytes) -> tuple[bytes, float]:
    from . import bee2_lib

    if not data:
        return b"", 0.0

    if len(key) != 32:
        raise ValueError("key must be 32 bytes")

    state = bee2_lib.memAlloc(bee2_lib.bashPrg_keep())
    key_vp, key_op = _to_octet(bee2_lib, key)
    buf_vp, _ = _to_octet(bee2_lib, data)

    try:
        # Инициализация состояния НЕ входит в crypto_time.
        bee2_lib.bashPrgStart(
            state,
            256,
            1,
            None,
            0,
            key_op,
            len(key),
        )

        bee2_lib.bashPrgEncrStart(state)

        # Чистое время обработки данных криптографической функцией.
        start = time.perf_counter()

        bee2_lib.bashPrgEncr(
            buf_vp,
            len(data),
            state,
        )

        end = time.perf_counter()

        crypto_time_ms = (end - start) * 1000

        encrypted = bytes(
            bee2_lib.cdata(buf_vp, len(data))
        )

        return encrypted, crypto_time_ms

    finally:
        bee2_lib.memFree(state)
        bee2_lib.memFree(key_vp)
        bee2_lib.memFree(buf_vp)


def _worker_decrypt(data: bytes, key: bytes) -> tuple[bytes, float]:
    from . import bee2_lib

    if not data:
        return b"", 0.0

    if len(key) != 32:
        raise ValueError("key must be 32 bytes")

    state = bee2_lib.memAlloc(bee2_lib.bashPrg_keep())
    key_vp, key_op = _to_octet(bee2_lib, key)
    buf_vp, _ = _to_octet(bee2_lib, data)

    try:
        # Инициализация состояния НЕ входит в crypto_time.
        bee2_lib.bashPrgStart(
            state,
            256,
            1,
            None,
            0,
            key_op,
            len(key),
        )

        bee2_lib.bashPrgDecrStart(state)

        # Чистое время обработки данных криптографической функцией.
        start = time.perf_counter()

        bee2_lib.bashPrgDecr(
            buf_vp,
            len(data),
            state,
        )

        end = time.perf_counter()

        crypto_time_ms = (end - start) * 1000

        decrypted = bytes(
            bee2_lib.cdata(buf_vp, len(data))
        )

        return decrypted, crypto_time_ms

    finally:
        bee2_lib.memFree(state)
        bee2_lib.memFree(key_vp)
        bee2_lib.memFree(buf_vp)


def hash256(data: bytes) -> bytes:
    pool = _get_pool()
    future = pool.submit(_worker_hash256, data)

    return future.result(timeout=60)


def encrypt(data: bytes, key: bytes) -> tuple[bytes, float]:
    pool = _get_pool()
    future = pool.submit(_worker_encrypt, data, key)

    return future.result(timeout=60)


def decrypt(data: bytes, key: bytes) -> tuple[bytes, float]:
    pool = _get_pool()
    future = pool.submit(_worker_decrypt, data, key)

    return future.result(timeout=60)