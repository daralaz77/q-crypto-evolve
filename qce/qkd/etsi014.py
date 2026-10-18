"""Adaptador de ETSI GS QKD 014 (API REST de entrega de claves de un KME a una aplicación, SAE) para el contrato de adaptadores QKD.

Qué es: un CLIENTE de la interfaz 014 (V1.1.1): `GET /api/v1/keys/{slave_SAE_ID}/status`, `POST .../enc_keys` (SAE maestra) y `POST .../dec_keys` (SAE esclava),
sobre HTTPS con autenticación mutua de la SAE y el KME. El `ssl.SSLContext` lo aporta quien construye el adaptador (use `qce.transport.tls13.client_context`
con certificado de cliente para exigir TLS 1.3 híbrido); este módulo no decide la política de transporte.

Qué NO es ni puede hacer (honestidad):
- La interfaz 014 solo ENTREGA CLAVES: no ofrece QBER, ε, amplificación de privacidad ni ningún testigo físico. Por eso se registra con el perfil `ETSI-014-KME`
  (qce/qkd/profiles.py): se confía en el operador del KME y en la ficha que una persona aprobó (saltos de confianza); no hay verificación de la física.
- No se ha probado contra ningún KME real. Solo contra el EMULADOR de `qce/qkd/etsi014_emulator.py`, que es una simulación y se declara como tal.
- La identidad del KME es el certificado fijado en el alta (huella SHA-256), no un desafío-respuesta.
Falla cerrado: respuestas con forma inesperada, claves de tamaño distinto del pedido, identificadores repetidos o más claves de las pedidas = error, nunca "mejor esfuerzo".
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import http.client
import json
import re
import socket
import ssl
import time
from typing import Callable

from ..core.errors import PolicyViolation
from .contract import (Capabilities, DeviceAdapter, ErrorCategory, KeyMaterial, KeyReference, KeyState, QKDDeviceError)

INTERFACE = "ETSI GS QKD 014 V1.1.1"
PROTOCOL = "ETSI-014-KME"
SAE_ID_RE = re.compile(r"^[A-Za-z0-9._:@-]{1,128}$")
KEY_ID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")   # key_ID: UUID (ETSI 014 §5.3)
MAX_RESPONSE = 1 << 20
KEY_SIZE_MIN, KEY_SIZE_MAX = 128, 4096


class HttpsTransport:
    """Transporte HTTPS real: una conexión nueva por petición, plazo, límite de respuesta."""

    def __init__(self, host: str, port: int, ssl_context: ssl.SSLContext, server_hostname: str | None = None, timeout: float = 10.0) -> None:
        self._host, self._port, self._ctx, self._sni, self._timeout = host, port, ssl_context, server_hostname or host, timeout

    def request(self, method: str, path: str, body: dict | None = None) -> tuple[int, bytes]:
        conn = http.client.HTTPSConnection(self._host, self._port, context=self._ctx, timeout=self._timeout)
        try:
            raw = socket.create_connection((self._host, self._port), timeout=self._timeout)
            conn.sock = self._ctx.wrap_socket(raw, server_hostname=self._sni)
            data = json.dumps(body).encode() if body is not None else None
            conn.request(method, path, body=data, headers={"Content-Type": "application/json", "Accept": "application/json"})
            resp = conn.getresponse()
            payload = resp.read(MAX_RESPONSE + 1)
            if len(payload) > MAX_RESPONSE:
                raise QKDDeviceError(ErrorCategory.INVALID_RESPONSE, "respuesta del KME demasiado grande")
            return resp.status, payload
        except QKDDeviceError:
            raise
        except socket.timeout:
            raise QKDDeviceError(ErrorCategory.SERVICE_UNAVAILABLE, "tiempo de espera agotado con el KME") from None
        except ssl.SSLError as exc:
            raise QKDDeviceError(ErrorCategory.AUTHENTICATION_FAILURE, f"fallo TLS con el KME ({type(exc).__name__})") from None
        except OSError as exc:
            raise QKDDeviceError(ErrorCategory.CONNECTION_FAILURE, f"no hay conexión con el KME ({type(exc).__name__})") from None
        finally:
            conn.close()

    def peer_certificate_der(self) -> bytes:
        try:
            raw = socket.create_connection((self._host, self._port), timeout=self._timeout)
            with self._ctx.wrap_socket(raw, server_hostname=self._sni) as s:
                der = s.getpeercert(binary_form=True)
        except socket.timeout:
            raise QKDDeviceError(ErrorCategory.SERVICE_UNAVAILABLE, "tiempo de espera agotado con el KME") from None
        except ssl.SSLError as exc:
            raise QKDDeviceError(ErrorCategory.AUTHENTICATION_FAILURE, f"fallo TLS con el KME ({type(exc).__name__})") from None
        except OSError as exc:
            raise QKDDeviceError(ErrorCategory.CONNECTION_FAILURE, f"no hay conexión con el KME ({type(exc).__name__})") from None
        if not der:
            raise QKDDeviceError(ErrorCategory.DEVICE_UNTRUSTED, "el KME no presentó certificado")
        return der


class Etsi014Adapter(DeviceAdapter):
    adapter_version = "etsi014-1.0"

    def __init__(self, device_id: str, transport, own_sae_id: str, peer_sae_id: str, role: str, key_size_bits: int = 256, is_simulation: bool = False,
                 ttl_s: float = 300.0, clock: Callable[[], float] = time.time) -> None:
        if role not in ("master", "slave"):
            raise PolicyViolation("el rol de la SAE es 'master' o 'slave'")
        for sae in (own_sae_id, peer_sae_id):
            if not SAE_ID_RE.match(sae or ""):
                raise PolicyViolation("identificador de SAE no válido")
        if not KEY_SIZE_MIN <= key_size_bits <= KEY_SIZE_MAX or key_size_bits % 8:
            raise PolicyViolation(f"tamaño de clave entre {KEY_SIZE_MIN} y {KEY_SIZE_MAX} bits y múltiplo de 8")
        self.device_id, self._t, self._own, self._peer, self._role = device_id, transport, own_sae_id, peer_sae_id, role
        self._bits, self._sim, self._ttl, self._clock = key_size_bits, bool(is_simulation), ttl_s, clock
        self._registry = None

    # ---- contrato -----------------------------------------------------------------------------------------------------
    def initialize(self, configuration_reference) -> None:
        self._registry = configuration_reference["registry"]

    def peer_certificate_fingerprint(self) -> bytes:
        return hashlib.sha256(self._t.peer_certificate_der()).digest()

    def authenticate_device(self) -> None:
        if self._registry is None:
            raise QKDDeviceError(ErrorCategory.DEVICE_UNTRUSTED, "adaptador sin inicializar")
        self._registry.authenticate_pinned_certificate(self)

    def get_capabilities(self) -> Capabilities:
        return Capabilities("ETSI-014", "KME", "desconocido", INTERFACE, (PROTOCOL,),
                            frozenset({"initialize", "authenticate_device", "get_capabilities", "get_health_status", "get_key_service_status",
                                       "acquire_key", "report_key_consumption", "shutdown"}),
                            self._sim, "mutual-TLS+certificate-pin", max_key_size_bytes=KEY_SIZE_MAX // 8, qkd_protocol=PROTOCOL)

    # ---- REST ---------------------------------------------------------------------------------------------------------------
    def _call(self, method: str, path: str, body: dict | None = None) -> dict:
        status, payload = self._t.request(method, path, body)
        if status != 200:
            msg = ""
            try:
                msg = str(json.loads(payload).get("message", ""))[:80]
            except (ValueError, AttributeError):
                pass
            cat = {400: ErrorCategory.PROTOCOL_MISMATCH, 401: ErrorCategory.AUTHENTICATION_FAILURE, 503: ErrorCategory.KEY_EXHAUSTION}.get(status, ErrorCategory.UNKNOWN_ERROR)
            raise QKDDeviceError(cat, f"el KME respondió {status}" + (f" ({msg})" if msg else ""))
        try:
            data = json.loads(payload)
        except ValueError:
            raise QKDDeviceError(ErrorCategory.INVALID_RESPONSE, "respuesta del KME que no es JSON") from None
        if not isinstance(data, dict):
            raise QKDDeviceError(ErrorCategory.INVALID_RESPONSE, "respuesta del KME con forma inesperada")
        return data

    def _status(self) -> dict:
        d = self._call("GET", f"/api/v1/keys/{self._peer}/status")
        ints = ("key_size", "stored_key_count", "max_key_count", "max_key_per_request", "max_key_size", "min_key_size")
        if not all(isinstance(d.get(k), int) and not isinstance(d.get(k), bool) and d[k] >= 0 for k in ints):
            raise QKDDeviceError(ErrorCategory.INVALID_RESPONSE, "estado del KME con campos inválidos o ausentes")
        return d

    def get_health_status(self) -> dict:
        d = self._status()
        return {"state": "OK", "stored_key_count": d["stored_key_count"]}

    def get_key_service_status(self, key_id: str | None = None) -> dict:
        d = self._status()
        # sin testigos físicos: solo lo que la interfaz 014 declara; el tamaño de clave que ENTREGA este adaptador es el que pidió
        return {"available_keys": d["stored_key_count"], "qber": None, "witnesses": {"key_size_bits": self._bits}}

    def _parse_keys(self, data: dict, expected_ids: list[str] | None, count: int) -> list[tuple[str, bytes]]:
        keys = data.get("keys")
        if not isinstance(keys, list) or len(keys) != count:
            raise QKDDeviceError(ErrorCategory.INVALID_RESPONSE, f"el KME debía entregar exactamente {count} clave(s)")
        out, seen = [], set()
        for k in keys:
            kid, b64 = (k.get("key_ID"), k.get("key")) if isinstance(k, dict) else (None, None)
            if not isinstance(kid, str) or not KEY_ID_RE.match(kid) or not isinstance(b64, str):
                raise QKDDeviceError(ErrorCategory.INVALID_RESPONSE, "clave del KME con key_ID o contenido inválidos")
            if kid in seen or (expected_ids is not None and kid not in expected_ids):
                raise QKDDeviceError(ErrorCategory.INTEGRITY_FAILURE, "key_ID repetido o no pedido")
            try:
                raw = base64.b64decode(b64, validate=True)
            except (binascii.Error, ValueError):
                raise QKDDeviceError(ErrorCategory.INVALID_RESPONSE, "contenido de clave que no es base64") from None
            if len(raw) * 8 != self._bits:
                raise QKDDeviceError(ErrorCategory.INTEGRITY_FAILURE, "el KME entregó una clave de tamaño distinto del pedido")
            seen.add(kid)
            out.append((kid, raw))
        return out

    def acquire_key(self, authorized_request: dict) -> tuple[KeyReference, KeyMaterial]:
        link = str(authorized_request.get("link_id", ""))
        if self._role == "master":
            data = self._call("POST", f"/api/v1/keys/{self._peer}/enc_keys", {"number": 1, "size": self._bits})
            [(kid, raw)] = self._parse_keys(data, None, 1)
        else:
            want = authorized_request.get("key_id")
            if not isinstance(want, str) or not KEY_ID_RE.match(want):
                raise QKDDeviceError(ErrorCategory.PROTOCOL_MISMATCH, "la SAE esclava necesita el key_ID (UUID) de la clave que pide")
            data = self._call("POST", f"/api/v1/keys/{self._peer}/dec_keys", {"key_IDs": [{"key_ID": want}]})
            [(kid, raw)] = self._parse_keys(data, [want], 1)
        now = self._clock()
        ref = KeyReference(kid, self.device_id, link, "ETSI-014", now, now + self._ttl, "session-key", KeyState.AVAILABLE, True, "", self._sim)
        return ref, KeyMaterial(raw)

    def report_key_consumption(self, key_reference: str) -> None:
        return None   # ETSI 014 no tiene operación de acuse: el KME borra la clave al entregarla; nada que informar

    def shutdown(self) -> None:
        return None
