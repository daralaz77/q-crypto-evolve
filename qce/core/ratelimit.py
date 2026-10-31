"""Límite de tasa por ORIGEN (cubo de fichas), en memoria y acotado.

Para qué: sin él, un origen puede abrir apretones TLS sin parar o retener claves QKD reservadas hasta `HANDSHAKE_TIMEOUT` (T5 y T43 del modelo de amenazas).
Es una defensa de CAPA DE APLICACIÓN: no sustituye a un cortafuegos ni a la protección contra DoS volumétrico de la red. El origen es lo que pase quien llama
(normalmente la IP del par): detrás de NAT muchos usuarios comparten origen, y un atacante con muchas IP lo esquiva.
"""
from __future__ import annotations

import ipaddress
import threading
import time
from collections import OrderedDict
from typing import Callable

from .errors import PolicyViolation


class RateLimited(PolicyViolation):
    """El origen superó su límite de intentos."""


class OriginRateLimiter:
    @staticmethod
    def origin_key(address: str) -> str:
        """Clave del cubo: IPv4 tal cual; IPv6 por su prefijo /64 (quien controla una red IPv6 suele controlar un /64 entero, y sin esto cada dirección sería «otro
        origen»); una IPv4 asignada a IPv6 cuenta como su IPv4; lo que no es una IP no se toca."""
        try:
            ip = ipaddress.ip_address(address.split("%", 1)[0])
        except ValueError:
            return address
        if ip.version == 6:
            return str(ip.ipv4_mapped) if ip.ipv4_mapped else str(ipaddress.ip_network((ip, 64), strict=False))
        return str(ip)

    def __init__(self, rate_per_s: float, burst: int, max_origins: int = 4096, clock: Callable[[], float] = time.monotonic) -> None:
        if rate_per_s <= 0 or burst < 1 or max_origins < 1:
            raise ValueError("parámetros de límite inválidos")
        self.rate, self.burst, self.max_origins, self._clock = rate_per_s, burst, max_origins, clock
        self._buckets: OrderedDict[str, tuple[float, float]] = OrderedDict()  # origen → (fichas, instante)
        self._lock = threading.Lock()
        self.denied = 0

    def allow(self, origin: str) -> bool:
        origin = self.origin_key(origin)
        now = self._clock()
        with self._lock:
            tokens, last = self._buckets.pop(origin, (float(self.burst), now))
            tokens = min(float(self.burst), tokens + max(0.0, now - last) * self.rate)
            ok = tokens >= 1.0
            if ok:
                tokens -= 1.0
            else:
                self.denied += 1
            self._buckets[origin] = (tokens, now)  # el más reciente al final
            while len(self._buckets) > self.max_origins:  # memoria acotada: se descarta el origen más antiguo (inactivo)
                self._buckets.popitem(last=False)
            return ok

    def check(self, origin: str) -> None:
        if not self.allow(origin):
            raise RateLimited("demasiados intentos desde este origen")

    @property
    def tracked_origins(self) -> int:
        return len(self._buckets)
