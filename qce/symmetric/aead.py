"""Cifrado autenticado con nonce determinista por contador (nunca aleatorio ni reutilizable)."""
from __future__ import annotations

import hashlib
import hmac as _hmac
import threading

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ..core.errors import AuthenticationFailure, PolicyViolation, ReplayDetected


def hkdf(ikm: bytes, info: bytes, length: int = 32, salt: bytes | None = None) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(ikm)


def ct_equal(a: bytes, b: bytes) -> bool:
    return _hmac.compare_digest(a, b)


def mac(key: bytes, data: bytes) -> bytes:
    return _hmac.new(key, data, hashlib.sha256).digest()


class SealingKey:
    """Una clave de sentido único. El contador solo avanza; reutilizar un nonce es imposible."""

    def __init__(self, aead: str, key: bytes, nonce_prefix: bytes, max_records: int = 2**32) -> None:
        if len(key) != 32:
            raise PolicyViolation("se exigen claves de 256 bits")
        if len(nonce_prefix) != 4:
            raise PolicyViolation("prefijo de nonce inválido")
        self._aead = ChaCha20Poly1305(key) if aead == "CHACHA20-POLY1305" else AESGCM(key)
        self._prefix = nonce_prefix
        self._next = 0
        self._max = max_records
        self._lock = threading.Lock()  # contador atómico también sin GIL

    @property
    def counter(self) -> int:
        return self._next

    def seal(self, plaintext: bytes, aad: bytes) -> tuple[int, bytes]:
        with self._lock:
            if self._next >= self._max:
                raise PolicyViolation("límite de registros por clave alcanzado: rotar")
            seq = self._next
            self._next += 1
        return seq, self._aead.encrypt(self._nonce(self._prefix, seq), plaintext, aad)

    @staticmethod
    def _nonce(prefix: bytes, seq: int) -> bytes:
        return prefix + seq.to_bytes(8, "big")


class OpeningKey:
    def __init__(self, aead: str, key: bytes, nonce_prefix: bytes, window: int = 64) -> None:
        self._aead = ChaCha20Poly1305(key) if aead == "CHACHA20-POLY1305" else AESGCM(key)
        self._prefix = nonce_prefix
        self._window = ReplayWindow(window)
        self._lock = threading.Lock()

    def open(self, seq: int, ciphertext: bytes, aad: bytes) -> bytes:
        # Se comprueba la repetición ANTES de aceptar, pero solo se registra tras autenticar.
        with self._lock:  # comprobar-autenticar-registrar de forma atómica (sin ventana de carrera)
            self._window.check(seq)
            try:
                pt = self._aead.decrypt(SealingKey._nonce(self._prefix, seq), ciphertext, aad)
            except InvalidTag as exc:
                raise AuthenticationFailure("etiqueta AEAD inválida") from exc
            self._window.accept(seq)
            return pt


class ReplayWindow:
    """Ventana deslizante estilo IPsec/DTLS."""

    def __init__(self, size: int = 64) -> None:
        self.size = size
        self.highest = -1
        self._seen: set[int] = set()

    def check(self, seq: int) -> None:
        if seq < 0:
            raise ReplayDetected("secuencia negativa")
        if seq <= self.highest - self.size:
            raise ReplayDetected("fuera de ventana (demasiado antiguo)")
        if seq in self._seen:
            raise ReplayDetected("secuencia repetida")

    def accept(self, seq: int) -> None:
        self._seen.add(seq)
        if seq > self.highest:
            self.highest = seq
        floor = self.highest - self.size
        self._seen = {s for s in self._seen if s > floor}
