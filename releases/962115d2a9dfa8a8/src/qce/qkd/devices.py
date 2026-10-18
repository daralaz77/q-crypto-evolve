"""Registro de dispositivos con identidad autenticada + adaptador SIMULADO con inyección de fallos.

El simulador NO es evidencia de seguridad física ni de distribución cuántica real: toda clave
que entrega lleva is_simulation=True y el broker la rechaza salvo que la política de laboratorio lo permita.
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Callable

from ..core.chainlog import ChainLog
from ..core.errors import AuthenticationFailure, PolicyViolation
from ..pqc.hybrid import HybridSigPrivateKey, hybrid_verify
from .contract import (Capabilities, DeviceAdapter, DeviceEvent, ErrorCategory, KeyMaterial, KeyReference,
                       KeyState, QKDDeviceError)

CTX = b"QCE-QKD/device-identity"


# ---- registro de dispositivos ---------------------------------------------------------------------
@dataclass
class DeviceRecord:
    device_id: str
    manufacturer: str
    model: str
    firmware_version: str
    public_key: bytes  # clave pública fijada en el alta (no secreta)
    approved_by: str
    trust_state: str = "ENROLLED"  # ENROLLED → TRUSTED | UNTRUSTED | REVIEW_REQUIRED
    last_successful_check: float = 0.0
    health_state: str = "UNKNOWN"


class DeviceRegistry:
    def __init__(self, audit: ChainLog | None = None, clock: Callable[[], float] = time.time) -> None:
        self._d: dict[str, DeviceRecord] = {}
        self._audit, self._clock = audit, clock

    def _log(self, event: str, device_id: str, **kw) -> None:
        if self._audit:
            self._audit.append({"event": event, "device_id": device_id, **kw})

    def enroll(self, device_id: str, manufacturer: str, model: str, firmware: str, public_key: bytes, approved_by: str) -> None:
        """El alta exige un responsable humano nombrado. Una conexión que 'responde' no basta."""
        if not approved_by.strip():
            raise PolicyViolation("alta de dispositivo sin autorización explícita")
        if device_id in self._d:
            raise PolicyViolation("dispositivo ya registrado: un cambio de confianza requiere revocar y dar de alta de nuevo")
        self._d[device_id] = DeviceRecord(device_id, manufacturer, model, firmware, public_key, approved_by)
        self._log("device_enrolled", device_id, approved_by=approved_by, model=model, firmware=firmware)

    def get(self, device_id: str) -> DeviceRecord:
        try:
            return self._d[device_id]
        except KeyError:
            raise QKDDeviceError(ErrorCategory.DEVICE_UNTRUSTED, "dispositivo no registrado") from None

    def authenticate(self, adapter: "SimulatedAdapter") -> None:
        """Desafío-respuesta con nonce fresco: una respuesta capturada no sirve en otra ocasión."""
        rec = self.get(adapter.device_id)
        if rec.trust_state in ("UNTRUSTED", "REVIEW_REQUIRED"):  # la identidad correcta NO basta para recuperar la confianza
            raise QKDDeviceError(ErrorCategory.DEVICE_UNTRUSTED, f"estado {rec.trust_state}: requiere aprobación humana (approve)")
        nonce = os.urandom(32)
        try:
            pub, sig = adapter.challenge_response(nonce)
        except QKDDeviceError:
            raise
        if pub != rec.public_key:
            rec.trust_state = "UNTRUSTED"
            self._log("identity_changed", rec.device_id)
            raise QKDDeviceError(ErrorCategory.DEVICE_UNTRUSTED, "la clave de identidad no coincide con la fijada en el alta")
        try:
            hybrid_verify(pub, rec.device_id.encode() + nonce, sig, CTX)
        except AuthenticationFailure:
            self._log("auth_failed", rec.device_id)
            raise QKDDeviceError(ErrorCategory.AUTHENTICATION_FAILURE, "prueba de identidad inválida") from None
        rec.trust_state, rec.last_successful_check = "TRUSTED", self._clock()
        self._log("auth_ok", rec.device_id)

    def approve(self, device_id: str, approved_by: str, firmware: str | None = None) -> None:
        """Único camino de vuelta a la confianza: una persona nombrada revisa (y fija el firmware verificado)."""
        if not approved_by.strip():
            raise PolicyViolation("la re-aprobación exige un responsable humano nombrado")
        r = self.get(device_id)
        if firmware:
            r.firmware_version = firmware
        r.trust_state = "ENROLLED"  # aún debe superar el desafío-respuesta para ser TRUSTED
        self._log("device_reapproved", device_id, approved_by=approved_by, firmware=r.firmware_version)

    def is_trusted(self, device_id: str) -> bool:
        r = self._d.get(device_id)
        return bool(r and r.trust_state == "TRUSTED")

    def set_untrusted(self, device_id: str, reason: str) -> None:
        self.get(device_id).trust_state = "UNTRUSTED"
        self._log("trust_revoked", device_id, reason=reason)

    def on_firmware_change(self, device_id: str, new_firmware: str) -> None:
        """Un firmware distinto al verificado exige nueva revisión humana: la confianza no se hereda."""
        r = self.get(device_id)
        if new_firmware != r.firmware_version:
            r.trust_state = "REVIEW_REQUIRED"
            self._log("firmware_changed", device_id, old=r.firmware_version, new=new_firmware)


# ---- enlace y adaptador simulados ---------------------------------------------------------------------
class SimulatedLink:
    """Genera material compartido para dos extremos. SIMULACIÓN: os.urandom, sin física cuántica."""

    def __init__(self, link_id: str) -> None:
        self.link_id = link_id
        self.ends: list[SimulatedAdapter] = []

    def generate(self, n: int = 1, size: int = 32, qber: float = 0.02) -> list[bytes]:
        ids = []
        for _ in range(n):
            kid = os.urandom(8).hex()
            secret = os.urandom(size)
            for e in self.ends:
                e._pool[kid] = [secret, e._clock(), qber]
            ids.append(kid)
        return ids


@dataclass
class SimulatedAdapter(DeviceAdapter):
    device_id: str
    link: SimulatedLink
    identity: HybridSigPrivateKey = field(default_factory=HybridSigPrivateKey.generate)
    faults: set[str] = field(default_factory=set)
    firmware: str = "SIM-1.0"
    key_ttl_s: float = 300.0
    clock: Callable[[], float] = time.time
    protocol: str = "BB84"
    spec: tuple = ()
    trusted_hops: int = 0
    adapter_version = "sim-1.0"

    def __post_init__(self) -> None:
        self._pool: dict[str, list] = {}
        self._consumed: set[str] = set()
        self._clock = self.clock
        self._registry: DeviceRegistry | None = None
        self.link.ends.append(self)

    # --- contrato ---
    def initialize(self, configuration_reference) -> None:
        self._registry = configuration_reference["registry"]

    def challenge_response(self, nonce: bytes) -> tuple[bytes, bytes]:
        self._maybe_fail()
        key = HybridSigPrivateKey.generate() if "bad_identity" in self.faults else self.identity
        return key.public_bytes, key.sign(self.device_id.encode() + nonce, CTX)

    def authenticate_device(self) -> None:
        if self._registry is None:
            raise QKDDeviceError(ErrorCategory.DEVICE_UNTRUSTED, "adaptador sin inicializar")
        self._registry.authenticate(self)

    def get_capabilities(self) -> Capabilities:
        return Capabilities("SIMULATION", "qce-simulated-qkd", self.firmware, "qce-contract-1",
                            (f"SIMULATED-{self.protocol}",),
                            frozenset({"initialize", "authenticate_device", "get_capabilities", "get_health_status",
                                       "get_key_service_status", "request_key_metadata", "acquire_key",
                                       "report_key_consumption", "shutdown"}),
                            True, "hybrid-signature-challenge", qkd_protocol=self.protocol, spec=self.spec)

    def _maybe_fail(self) -> None:
        if "connection_loss" in self.faults:
            raise QKDDeviceError(ErrorCategory.CONNECTION_FAILURE, "enlace de control caído")
        if "latency" in self.faults:
            raise QKDDeviceError(ErrorCategory.SERVICE_UNAVAILABLE, "tiempo de espera agotado")

    def get_health_status(self) -> dict:
        self._maybe_fail()
        if "health_fail" in self.faults:
            raise QKDDeviceError(ErrorCategory.DEVICE_HEALTH_FAILURE, "autodiagnóstico del dispositivo falló")
        return {"state": "OK", "firmware": self.firmware}

    def get_key_service_status(self, key_id: str | None = None) -> dict:
        self._maybe_fail()
        avail = [k for k in self._pool if k not in self._consumed]
        if key_id is not None:
            avail = [k for k in avail if k == key_id]  # testigos de LA clave pedida
        qber = 0.25 if "eavesdropper" in self.faults else (max((self._pool[k][2] for k in avail), default=0.0))
        return {"available_keys": len(avail), "qber": qber, "witnesses": self._witnesses(avail[0] if avail else "", qber)}

    def _witnesses(self, key_id: str, qber: float) -> dict:
        """Testigos SIMULADOS y plausibles para el protocolo elegido; los fallos inyectables los rompen uno a uno."""
        w = {"key_id": key_id, "epsilon": 1e-10, "privacy_amplification": True, "trusted_hops": self.trusted_hops,
             "qber": qber, "decoy_ok": True, "relay_holds_key": False, "chsh_s": 2.7, "phase_error": 0.02,
             "excess_noise": 0.01, "shot_noise_calibrated": True, "loophole_free": True}
        f = self.faults
        if "chsh_low" in f: w["chsh_s"] = 1.9
        if "chsh_impossible" in f: w["chsh_s"] = 3.2
        if "no_pa" in f: w["privacy_amplification"] = False
        if "epsilon_big" in f: w["epsilon"] = 1e-3
        if "decoy_bad" in f: w["decoy_ok"] = False
        if "relay_leaks" in f: w["relay_holds_key"] = True
        if "noise_high" in f: w["excess_noise"] = 0.9
        if "uncalibrated" in f: w["shot_noise_calibrated"] = False
        if "phase_high" in f: w["phase_error"] = 0.4
        if "hops" in f: w["trusted_hops"] = 2
        if "witness_missing" in f: w.pop("epsilon")
        if "stale_witness" in f: w["key_id"] = "otra-clave"
        if "loopholes" in f: w["loophole_free"] = False
        return w

    def request_key_metadata(self, request_context: dict) -> list[KeyReference]:
        self._maybe_fail()
        now = self._clock()
        return [KeyReference(k, self.device_id, self.link.link_id, "SIM", v[1], v[1] + self.key_ttl_s, "session-key",
                             KeyState.AVAILABLE, is_simulation=True)
                for k, v in self._pool.items() if k not in self._consumed]

    def acquire_key(self, authorized_request: dict) -> tuple[KeyReference, KeyMaterial]:
        self._maybe_fail()
        if "malformed" in self.faults:
            return {"unexpected": "shape"}, b"raw"  # type: ignore[return-value]
        wanted = authorized_request.get("key_id")
        candidates = [wanted] if wanted else [k for k in self._pool if k not in self._consumed]
        candidates = [k for k in candidates if k in self._pool and k not in self._consumed]
        if not candidates:
            raise QKDDeviceError(ErrorCategory.KEY_EXHAUSTION, "sin material de clave disponible")
        kid = candidates[0]
        secret, created, _ = self._pool[kid]
        self._consumed.add(kid)  # el dispositivo entrega cada key_ID una sola vez
        if "restart_mid_op" in self.faults:
            raise QKDDeviceError(ErrorCategory.CONNECTION_FAILURE, "reinicio durante la operación")
        ref = KeyReference(kid, self.device_id, self.link.link_id, "SIM", created, created + self.key_ttl_s,
                           "session-key", KeyState.AVAILABLE, integrity_ok="tamper" not in self.faults, is_simulation=True)
        return ref, KeyMaterial(secret)

    def report_key_consumption(self, key_reference: str) -> None:
        self._maybe_fail()

    def handle_device_event(self, event: DeviceEvent) -> None:
        if event.kind == "firmware_changed" and self._registry:
            self._registry.on_firmware_change(self.device_id, event.detail["version"])

    def shutdown(self) -> None:
        self._pool.clear()
