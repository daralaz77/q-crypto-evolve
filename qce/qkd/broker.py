"""Gestor de claves QKD: único punto por el que el material llega a los consumidores.

Garantías que prueban las pruebas (no que 'son seguras por venir de QKD'):
- falla CERRADO: sin fallback silencioso a criptografía clásica;
- solo dispositivos autenticados y de confianza; las simulaciones se rechazan salvo política de laboratorio;
- cada key_ID se entrega una sola vez; reserva por consumidor; caducidad; cuarentena por integridad/QBER;
- el material nunca aparece en metadatos, excepciones ni registros.
"""
from __future__ import annotations

import time
from typing import Callable

from ..core.chainlog import ChainLog
from ..core.errors import PolicyViolation, QKDAnomaly
from ..core.policy import Policy
from .contract import (DeviceAdapter, ErrorCategory, KeyMaterial, KeyReference, KeyState, QKDDeviceError)
from . import profiles
from .devices import DeviceRegistry


class KeyBroker:
    def __init__(self, policy: Policy, registry: DeviceRegistry, audit: ChainLog | None = None,
                 clock: Callable[[], float] = time.time, allowed_consumers: dict[str, set[str]] | None = None) -> None:
        self.policy, self.registry, self._audit, self._clock = policy, registry, audit, clock
        self._allowed = allowed_consumers or {}
        self._adapters: dict[str, DeviceAdapter] = {}  # link_id → adaptador
        self._refs: dict[str, KeyReference] = {}
        self._mat: dict[str, KeyMaterial] = {}
        self._link_blocked: dict[str, str] = {}
        self._caps: dict[str, object] = {}

    def _log(self, event: str, **kw) -> None:
        if self._audit:
            self._audit.append({"event": event, **kw})  # solo ids opacos y estados

    # ---- alta de enlaces ---------------------------------------------------------------------------
    def attach(self, link_id: str, adapter: DeviceAdapter) -> None:
        caps = adapter.get_capabilities()
        rec = self.registry.get(getattr(adapter, "device_id", ""))  # sin alta humana no hay confianza
        if rec.protocol and caps.qkd_protocol != rec.protocol:  # el dispositivo no puede cambiar de protocolo por su cuenta
            raise QKDDeviceError(ErrorCategory.DEVICE_UNTRUSTED, "el protocolo declarado no coincide con el fijado en el alta")
        protocol = rec.protocol or caps.qkd_protocol
        if caps.is_simulation and not self.policy.allow_simulated_qkd:
            self._log("attach_rejected", link=link_id, reason="simulation")
            raise PolicyViolation("dispositivo simulado rechazado por la política (producción)")
        prof = profiles.profile_for(protocol)
        if prof.assurance < profiles.Assurance(self.policy.min_assurance) or prof.assurance == profiles.Assurance.NONE:
            self._log("attach_rejected", link=link_id, reason="assurance", protocol=prof.protocol.value)
            raise PolicyViolation(f"protocolo {prof.protocol.value} (garantía {prof.assurance.name}) por debajo de la política")
        needed = {"authenticate_device", "acquire_key", "get_health_status", "get_key_service_status"}
        if not needed <= caps.supported_operations:
            raise QKDDeviceError(ErrorCategory.PROTOCOL_MISMATCH, f"faltan operaciones: {sorted(needed - caps.supported_operations)}")
        adapter.authenticate_device()
        if not self.registry.is_trusted(getattr(adapter, "device_id", "")):
            raise QKDDeviceError(ErrorCategory.DEVICE_UNTRUSTED, "el dispositivo no quedó en estado de confianza")
        # Se publica TODO junto y solo al final: un attach fallido no puede alterar un enlace ya conectado (hallazgo M3)
        self._adapters[link_id] = adapter
        self._caps[link_id] = (protocol, rec.spec, bool(caps.is_simulation))
        self._log("attached", link=link_id)

    def _guard(self, link_id: str) -> DeviceAdapter:
        if link_id in self._link_blocked:
            raise QKDAnomaly(f"enlace en cuarentena: {self._link_blocked[link_id]}")
        ad = self._adapters.get(link_id)
        if ad is None:
            raise QKDDeviceError(ErrorCategory.SERVICE_UNAVAILABLE, "enlace sin adaptador")
        if not self.registry.is_trusted(ad.device_id):  # se reevalúa en CADA operación
            raise QKDDeviceError(ErrorCategory.DEVICE_UNTRUSTED, "confianza revocada o pendiente de revisión")
        return ad

    # ---- adquisición -----------------------------------------------------------------------------------
    def _check_witnesses(self, link_id: str, ad, key_id: str | None) -> dict:
        """Evalúa los testigos del perfil del protocolo. Falla cerrado: lo imposible, ausente o sospechoso no pasa."""
        st = ad.get_key_service_status(key_id)
        protocol, spec, _sim = self._caps[link_id]
        w = st.get("witnesses") or {}
        if not isinstance(w, dict):
            raise QKDDeviceError(ErrorCategory.INVALID_RESPONSE, "testigos con forma inesperada")
        w = dict(w)
        if "qber" in w and w["qber"] != st.get("qber"):  # dos fuentes del mismo dato que no coinciden = respuesta inconsistente
            self._log("witness_invalid", link=link_id, detail="qber inconsistente")
            raise QKDDeviceError(ErrorCategory.INVALID_RESPONSE, "QBER del estado y de los testigos no coinciden")
        evidence = {**w, "qber": st.get("qber")}  # el QBER del estado es la fuente; los testigos no pueden sobrescribirlo
        findings = profiles.evaluate(profiles.profile_for(protocol), evidence, self.policy, spec=dict(spec))
        if any(f.kind == "invalid" for f in findings):
            self._log("witness_invalid", link=link_id, detail=findings[0].message[:80])
            raise QKDDeviceError(ErrorCategory.INVALID_RESPONSE, findings[0].message)
        if any(f.kind == "anomaly" for f in findings):
            msg = next(f.message for f in findings if f.kind == "anomaly")
            self._link_blocked[link_id] = msg
            self._log("link_quarantined", link=link_id, reason=msg[:80])
            raise QKDAnomaly(f"{msg}; el enlace queda en cuarentena")
        if findings:
            self._log("witness_policy", link=link_id, detail=findings[0].message[:80])
            raise PolicyViolation(findings[0].message)
        return evidence

    def _normalize(self, ref: KeyReference, ad: DeviceAdapter, link_id: str) -> KeyReference:
        """El broker NO confía en los metadatos que declara el dispositivo: enlace, origen, estado y caducidad los pone él."""
        def fin(x) -> bool:
            return isinstance(x, (int, float)) and not isinstance(x, bool) and x == x and abs(x) != float("inf")
        if not (isinstance(ref.key_reference, str) and 0 < len(ref.key_reference) <= 128 and fin(ref.creation_time)
                and fin(ref.expires_at) and ref.integrity_ok in (True, False)):
            raise QKDDeviceError(ErrorCategory.INVALID_RESPONSE, "metadatos de clave inválidos")
        now = self._clock()
        expires = min(ref.expires_at, now + self.policy.max_key_ttl_s)
        if expires <= now:
            raise QKDDeviceError(ErrorCategory.KEY_EXPIRED, "la clave llega ya caducada")
        return KeyReference(ref.key_reference, ad.device_id, link_id, str(ref.protocol_context)[:64], float(ref.creation_time), float(expires),
                            "session-key", KeyState.AVAILABLE, bool(ref.integrity_ok), "", bool(ref.is_simulation) or self._caps[link_id][2])

    def refill(self, link_id: str, count: int = 1, key_id: str | None = None) -> list[str]:
        ad = self._guard(link_id)
        ad.get_health_status()
        got = []
        for _ in range(count):
            evidence = self._check_witnesses(link_id, ad, key_id)  # por CADA clave: testigos frescos
            req = {"link_id": link_id, **({"key_id": key_id} if key_id else {})}
            try:
                res = ad.acquire_key(req)
            except QKDDeviceError as exc:
                self._log("acquire_failed", link=link_id, category=exc.category.value)
                raise
            if not (isinstance(res, tuple) and len(res) == 2 and isinstance(res[0], KeyReference) and isinstance(res[1], KeyMaterial)):
                self._log("acquire_failed", link=link_id, category="INVALID_RESPONSE")
                raise QKDDeviceError(ErrorCategory.INVALID_RESPONSE, "respuesta con forma inesperada")
            ref, mat = res
            try:
                ref = self._normalize(ref, ad, link_id)
            except QKDDeviceError:
                mat.destroy()
                raise
            if evidence.get("key_id") != ref.key_reference:  # testigos de otra clave = evidencia reutilizada
                mat.destroy()
                self._log("witness_mismatch", link=link_id)
                raise QKDDeviceError(ErrorCategory.INTEGRITY_FAILURE, "los testigos no corresponden a la clave entregada")
            if ref.key_reference in self._refs:
                mat.destroy()
                raise QKDDeviceError(ErrorCategory.INTEGRITY_FAILURE, "key_ID duplicado")
            if ref.is_simulation and not self.policy.allow_simulated_qkd:
                mat.destroy()
                raise PolicyViolation("clave simulada rechazada por la política")
            if not ref.integrity_ok:
                ref.state = KeyState.QUARANTINED
                self._refs[ref.key_reference] = ref
                mat.destroy()
                self._log("key_quarantined", key=ref.key_reference, reason="integrity")
                raise QKDDeviceError(ErrorCategory.INTEGRITY_FAILURE, "integridad de la clave no verificable: en cuarentena")
            self._refs[ref.key_reference], self._mat[ref.key_reference] = ref, mat
            self._log("key_available", key=ref.key_reference, link=link_id)
            got.append(ref.key_reference)
        return got

    # ---- reserva y consumo -----------------------------------------------------------------------------------
    def _authorized(self, link_id: str, consumer: str) -> None:
        if consumer not in self._allowed.get(link_id, set()):
            self._log("consumer_denied", link=link_id, consumer=consumer)
            raise PolicyViolation("consumidor no autorizado para este enlace")

    def _refresh(self, ref: KeyReference) -> None:
        if ref.state in (KeyState.AVAILABLE, KeyState.RESERVED) and self._clock() >= ref.expires_at:
            ref.state = KeyState.EXPIRED
            m = self._mat.pop(ref.key_reference, None)
            if m:
                m.destroy()

    def reserve(self, link_id: str, consumer: str, key_id: str | None = None) -> str:
        self._authorized(link_id, consumer)
        self._guard(link_id)
        for r in self._refs.values():
            self._refresh(r)
        pool = [r for r in self._refs.values() if r.peer_or_link_id == link_id and r.state is KeyState.AVAILABLE
                and (key_id is None or r.key_reference == key_id)]
        if not pool:
            raise QKDDeviceError(ErrorCategory.KEY_EXHAUSTION, "sin claves disponibles en el broker")
        ref = pool[0]
        ref.state, ref.reserved_by = KeyState.RESERVED, consumer
        self._log("key_reserved", key=ref.key_reference, consumer=consumer)
        return ref.key_reference

    def consume(self, key_reference: str, consumer: str) -> bytes:
        ref = self._refs.get(key_reference)
        if ref is None:
            raise QKDDeviceError(ErrorCategory.KEY_EXPIRED, "referencia desconocida")
        self._refresh(ref)
        if ref.state is not KeyState.RESERVED or ref.reserved_by != consumer:
            self._log("consume_denied", key=key_reference, state=ref.state.value)
            raise QKDDeviceError(ErrorCategory.KEY_EXPIRED, f"clave no utilizable (estado {ref.state.value})")
        self._guard(ref.peer_or_link_id)
        secret = self._mat.pop(key_reference).reveal()
        ref.state = KeyState.CONSUMED
        try:
            self._adapters[ref.peer_or_link_id].report_key_consumption(key_reference)
        except QKDDeviceError:
            self._log("consumption_report_failed", key=key_reference)  # la clave ya está CONSUMED: nunca se reutiliza
        self._log("key_consumed", key=key_reference, consumer=consumer)
        return secret

    def take(self, link_id: str, consumer: str, key_id: str | None = None) -> tuple[bytes, bytes]:
        """(key_id, material) — para el ClientHello/ServerHandshake.qkd_lookup."""
        if key_id and key_id not in self._refs:  # extremo receptor: pide por key_ID (como en ETSI GS QKD 014)
            self._authorized(link_id, consumer)
            self.refill(link_id, 1, key_id)
        ref = self.reserve(link_id, consumer, key_id)
        return ref.encode(), self.consume(ref, consumer)

    # ---- control --------------------------------------------------------------------------------------------------
    def revoke(self, key_reference: str, reason: str) -> None:
        ref = self._refs[key_reference]
        ref.state = KeyState.REVOKED
        m = self._mat.pop(key_reference, None)
        if m:
            m.destroy()
        self._log("key_revoked", key=key_reference, reason=reason)

    def metadata(self, key_reference: str) -> KeyReference:
        r = self._refs[key_reference]
        self._refresh(r)
        return r  # los metadatos no contienen secreto por construcción

    def status(self, link_id: str) -> dict:
        for r in self._refs.values():
            self._refresh(r)
        counts: dict[str, int] = {}
        for r in self._refs.values():
            if r.peer_or_link_id == link_id:
                counts[r.state.value] = counts.get(r.state.value, 0) + 1
        return {"blocked": self._link_blocked.get(link_id), "keys": counts}
