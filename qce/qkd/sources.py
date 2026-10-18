"""Fuentes de claves de un solo uso con reserva, para los consumidores de claves QKD (capa QIL1 y TLS 1.3 con PSK).

Contrato (`KeySource`): `reserve(kid) -> clave | None` marca la clave como en uso (nadie más la obtiene), `commit(kid)` la consume para siempre y
`release(kid)` la devuelve. Así quien solo conoce el identificador no puede gastarla (T43). Sin dependencia de TLS: se puede importar en cualquier orden.
"""
from __future__ import annotations

import threading

from ..core.errors import PolicyViolation


class OneTimeKeys:
    """Almacén de laboratorio de claves de un solo uso (hilo-seguro) con reserva. En un despliegue real la fuente es el KeyBroker (`BrokerSource`)."""

    def __init__(self, keys: dict[bytes, bytes] | None = None) -> None:
        self._keys, self._reserved, self._lock = dict(keys or {}), set(), threading.Lock()

    def add(self, key_id: bytes, key: bytes) -> None:
        with self._lock:
            self._keys[bytes(key_id)] = bytes(key)

    def reserve(self, key_id: bytes) -> bytes | None:
        kid = bytes(key_id)
        with self._lock:
            if kid in self._reserved or kid not in self._keys:
                return None
            self._reserved.add(kid)
            return self._keys[kid]

    def commit(self, key_id: bytes) -> None:
        with self._lock:
            self._keys.pop(bytes(key_id), None)
            self._reserved.discard(bytes(key_id))

    def release(self, key_id: bytes) -> None:
        with self._lock:
            self._reserved.discard(bytes(key_id))

    def take(self, key_id: bytes) -> bytes | None:
        """Entrega única inmediata (lado cliente o pruebas): reserva y consume."""
        key = self.reserve(key_id)
        if key is not None:
            self.commit(key_id)
        return key


class BrokerSource:
    """Adapta el KeyBroker (reserva, consumo único, política, cuarentena) a la fuente del servidor. Cualquier fallo del broker = sin clave."""

    def __init__(self, broker, link_id: str, consumer: str) -> None:
        self._b, self._link, self._consumer = broker, link_id, consumer

    def reserve(self, key_id: bytes) -> bytes | None:
        from .contract import QKDDeviceError
        from ..core.errors import QKDAnomaly
        try:
            return self._b.hold(self._link, self._consumer, key_id.decode("ascii"))
        except (QKDDeviceError, QKDAnomaly, PolicyViolation, UnicodeDecodeError):
            return None

    def commit(self, key_id: bytes) -> None:
        self._b.consume(key_id.decode("ascii"), self._consumer)

    def release(self, key_id: bytes) -> None:
        self._b.release(key_id.decode("ascii"), self._consumer)
