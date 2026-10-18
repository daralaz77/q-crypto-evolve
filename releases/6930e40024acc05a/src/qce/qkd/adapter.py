"""Interfaz QKD independiente + monitor de canal + ingesta de claves.

IMPORTANTE: `SimulatedQKDDevice` es una SIMULACIÓN estadística. No produce mediciones físicas,
sus claves no tienen garantías de teoría de la información y la política las rechaza por defecto.
Para hardware real hay que implementar `QKDDevice` (p. ej. sobre ETSI GS QKD 014) — no incluido:
no hay dispositivo en este entorno y no se finge uno.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import random
from abc import ABC, abstractmethod
from dataclasses import dataclass

from ..core.errors import AuthenticationFailure, PolicyViolation, QKDAnomaly
from ..core.policy import Policy


@dataclass(frozen=True)
class QKDKey:
    key_id: bytes
    key: bytes
    qber: float  # tasa de error de bit observada en el canal cuántico
    source: str  # "hardware:<modelo>" | "SIMULATION"
    tag: bytes  # MAC clásico (autenticación del canal clásico)


class QKDDevice(ABC):
    is_simulation: bool

    @abstractmethod
    def fetch_key(self, peer_id: str, size: int) -> QKDKey: ...


class SimulatedQKDDevice(QKDDevice):
    """Simulación de laboratorio. Permite inyectar un espía para probar el monitor."""

    is_simulation = True

    def __init__(self, auth_key: bytes, eavesdropper: bool = False, seed: int | None = None) -> None:
        self._auth, self._eve = auth_key, eavesdropper
        self._rng = random.Random(seed)  # solo para el ruido simulado, NUNCA para la clave

    def fetch_key(self, peer_id: str, size: int = 32) -> QKDKey:
        key, key_id = os.urandom(size), os.urandom(16)
        # BB84 con espía intercepta-reenvía produce ~25 % de error; sin espía, ruido del canal ~1–3 %.
        qber = self._rng.uniform(0.22, 0.28) if self._eve else self._rng.uniform(0.01, 0.03)
        return QKDKey(key_id, key, qber, "SIMULATION", sign_key(self._auth, key_id, key, qber))


def sign_key(auth_key: bytes, key_id: bytes, key: bytes, qber: float) -> bytes:
    msg = key_id + hashlib.sha256(key).digest() + f"{qber:.6f}".encode()
    return hmac.new(auth_key, msg, hashlib.sha256).digest()


class ChannelMonitor:
    def __init__(self, policy: Policy) -> None:
        self.policy = policy
        self.alerts: list[str] = []

    def assess(self, k: QKDKey) -> None:
        if not 0.0 <= k.qber <= 0.5 or k.qber != k.qber:
            raise QKDAnomaly("QBER fuera de rango físico")
        if k.qber >= self.policy.qber_abort:
            self.alerts.append(f"ABORT qber={k.qber:.3f}")
            raise QKDAnomaly(f"QBER {k.qber:.3f} ≥ {self.policy.qber_abort}: posible espionaje, clave descartada")
        if k.qber >= self.policy.qber_warn:
            self.alerts.append(f"WARN qber={k.qber:.3f}")


class QKDIngestor:
    """Acepta claves QKD solo si: canal clásico autenticado, QBER aceptable y fuente admisible."""

    def __init__(self, policy: Policy, auth_key: bytes) -> None:
        self.policy, self._auth = policy, auth_key
        self.monitor = ChannelMonitor(policy)
        self._keys: dict[bytes, bytes] = {}
        self._seen: set[bytes] = set()  # TODOS los key_id vistos, incluso los ya consumidos

    def ingest(self, k: QKDKey) -> None:
        if k.source == "SIMULATION" and not self.policy.allow_simulated_qkd:
            raise PolicyViolation("clave QKD simulada rechazada por la política (producción)")
        if not hmac.compare_digest(k.tag, sign_key(self._auth, k.key_id, k.key, k.qber)):
            raise AuthenticationFailure("etiqueta del canal clásico QKD inválida")
        if k.key_id in self._seen:
            raise PolicyViolation("key_id QKD repetido")
        self.monitor.assess(k)
        self._seen.add(k.key_id)
        self._keys[k.key_id] = k.key

    def take(self, key_id: bytes) -> bytes | None:
        """Entrega única: la clave QKD se consume (no se reutiliza entre sesiones)."""
        return self._keys.pop(key_id, None)
