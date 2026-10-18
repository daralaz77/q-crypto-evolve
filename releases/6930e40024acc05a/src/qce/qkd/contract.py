"""Contrato común de adaptadores QKD (independiente del fabricante) — skill q-crypto-qkd-adapters.

El adaptador TRANSPORTA capacidades; no crea garantías que el dispositivo no ofrece.
Toda operación no soportada se declara como tal (nunca se simula un éxito).
"""
from __future__ import annotations

from abc import ABC
from dataclasses import dataclass, field
from enum import Enum

from ..core.errors import QCEError


class ErrorCategory(str, Enum):
    CONNECTION_FAILURE = "CONNECTION_FAILURE"
    AUTHENTICATION_FAILURE = "AUTHENTICATION_FAILURE"
    DEVICE_UNTRUSTED = "DEVICE_UNTRUSTED"
    SERVICE_UNAVAILABLE = "SERVICE_UNAVAILABLE"
    KEY_EXHAUSTION = "KEY_EXHAUSTION"
    KEY_EXPIRED = "KEY_EXPIRED"
    INVALID_RESPONSE = "INVALID_RESPONSE"
    PROTOCOL_MISMATCH = "PROTOCOL_MISMATCH"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"
    DEVICE_HEALTH_FAILURE = "DEVICE_HEALTH_FAILURE"
    UNKNOWN_ERROR = "UNKNOWN_ERROR"


class QKDDeviceError(QCEError):
    """Error con categoría interna; el mensaje NUNCA contiene material de clave."""

    def __init__(self, category: ErrorCategory, message: str) -> None:
        super().__init__(f"{category.value}: {message}")
        self.category = category


class KeyState(str, Enum):
    AVAILABLE = "AVAILABLE"
    RESERVED = "RESERVED"
    CONSUMED = "CONSUMED"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"
    QUARANTINED = "QUARANTINED"
    UNAVAILABLE = "UNAVAILABLE"


class KeyMaterial:
    """Contenedor de secreto: sin repr/str/pickle útil, para que no llegue a trazas ni excepciones."""

    __slots__ = ("_b",)

    def __init__(self, data: bytes) -> None:
        self._b = bytearray(data)

    def reveal(self) -> bytes:
        if self._b is None:
            raise QKDDeviceError(ErrorCategory.KEY_EXPIRED, "material ya destruido")
        return bytes(self._b)

    def destroy(self) -> None:
        if self._b is not None:
            for i in range(len(self._b)):
                self._b[i] = 0  # mejor esfuerzo; ver LIMITATIONS.md
            self._b = None

    def __repr__(self) -> str:
        return "<KeyMaterial [REDACTED]>"

    __str__ = __repr__

    def __reduce__(self):
        raise TypeError("KeyMaterial no es serializable")


@dataclass(frozen=True)
class Capabilities:
    manufacturer: str
    model: str
    firmware_version: str
    interface_version: str
    supported_protocols: tuple[str, ...]
    supported_operations: frozenset[str]
    is_simulation: bool
    authentication_method: str
    max_key_size_bytes: int = 64


@dataclass
class KeyReference:
    """Metadatos autorizados de una clave: NUNCA incluyen el contenido secreto."""

    key_reference: str  # identificador opaco (el key_ID del dispositivo)
    source_device_id: str
    peer_or_link_id: str
    protocol_context: str
    creation_time: float
    expires_at: float
    permitted_usage: str
    state: KeyState = KeyState.AVAILABLE
    integrity_ok: bool = True
    reserved_by: str = ""
    is_simulation: bool = False


@dataclass
class DeviceEvent:
    kind: str  # p.ej. "restart", "qber_alarm", "firmware_changed"
    detail: dict = field(default_factory=dict)


class DeviceAdapter(ABC):
    """Contrato lógico. Los métodos no soportados lanzan PROTOCOL_MISMATCH: capacidad NO SOPORTADA."""

    adapter_version = "0"

    def _unsupported(self, op: str):
        raise QKDDeviceError(ErrorCategory.PROTOCOL_MISMATCH, f"operación no soportada por este adaptador: {op}")

    def initialize(self, configuration_reference: str) -> None: self._unsupported("initialize")
    def authenticate_device(self) -> None: self._unsupported("authenticate_device")
    def get_capabilities(self) -> Capabilities: self._unsupported("get_capabilities")
    def get_health_status(self) -> dict: self._unsupported("get_health_status")
    def get_key_service_status(self) -> dict: self._unsupported("get_key_service_status")
    def request_key_metadata(self, request_context: dict) -> list[KeyReference]: self._unsupported("request_key_metadata")
    def acquire_key(self, authorized_request: dict) -> tuple[KeyReference, KeyMaterial]: self._unsupported("acquire_key")
    def acknowledge_key_usage(self, key_reference: str) -> None: self._unsupported("acknowledge_key_usage")
    def report_key_consumption(self, key_reference: str) -> None: self._unsupported("report_key_consumption")
    def handle_device_event(self, event: DeviceEvent) -> None: self._unsupported("handle_device_event")
    def close_session(self) -> None: self._unsupported("close_session")
    def shutdown(self) -> None: self._unsupported("shutdown")
