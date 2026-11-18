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
        if isinstance(ip, ipaddress.IPv6Address):
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


class ConnectionGuard:
    """Tope de conexiones SIMULTÁNEAS: global y por origen (el origen se agrupa igual que en `OriginRateLimiter`: IPv6 por su /64).

    Sin el tope por origen, un solo origen llena el tope global y deja fuera a todos los demás. Con él, ningún origen ocupa más de `max_per_origin` huecos
    (los demás siguen entrando mientras quede sitio global). Memoria acotada: solo se guardan los orígenes con conexiones ACTIVAS (se borran al llegar a 0).
    Detrás de NAT muchos usuarios comparten origen: ese límite los afecta a todos a la vez; un atacante con muchas direcciones lo esquiva (el tope global sigue
    protegiendo el proceso)."""

    def __init__(self, max_total: int, max_per_origin: int | None = None) -> None:
        if max_total < 1 or (max_per_origin is not None and max_per_origin < 1):
            raise ValueError("parámetros de límite inválidos")
        self.max_total, self.max_per_origin = max_total, max_per_origin
        self._lock = threading.Lock()
        self._active: dict[str, int] = {}
        self._total = 0

    def acquire(self, origin: str) -> str | None:
        """None si la conexión se admite (y ocupa un hueco); si no, el motivo: 'busy' (tope global) o 'origin' (tope de ese origen)."""
        key = OriginRateLimiter.origin_key(origin)
        with self._lock:
            if self._total >= self.max_total:
                return "busy"
            if self.max_per_origin is not None and self._active.get(key, 0) >= self.max_per_origin:
                return "origin"
            self._active[key] = self._active.get(key, 0) + 1
            self._total += 1
            return None

    def release(self, origin: str) -> None:
        key = OriginRateLimiter.origin_key(origin)
        with self._lock:
            n = self._active.get(key, 0)
            if n <= 0:
                return  # liberar de más no hace negativo el contador
            if n == 1:
                del self._active[key]
            else:
                self._active[key] = n - 1
            self._total -= 1

    @property
    def active(self) -> int:
        return self._total

    @property
    def tracked_origins(self) -> int:
        return len(self._active)
