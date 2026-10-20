"""Mutantes de qkd / otros (24). Archivos que rompen: qce/qkd/adapter.py, qce/qkd/contract.py, qce/qkd/devices.py, qce/qkd/sources.py."""
from ._base import Mutant as M

MUTANTS = [
    M("qkd-sim-allowed-in-prod", "qce/qkd/adapter.py", (("if k.source == \"SIMULATION\" and not self.policy.allow_simulated_qkd:", "if False:"),), "simulación ≠ hardware"),
    M("qkd-auth-off", "qce/qkd/adapter.py", (("if not hmac.compare_digest(k.tag,", "if False and not hmac.compare_digest(k.tag,"),), "canal clásico autenticado"),
    M("qkd-qber-boundary", "qce/qkd/adapter.py", (("if k.qber >= self.policy.qber_abort:", "if k.qber > self.policy.qber_abort:"),), "umbral QBER"),
    M("qkd-qber-nan", "qce/qkd/adapter.py", (("if not 0.0 <= k.qber <= 0.5 or k.qber != k.qber:", "if False:"),), "QBER físicamente válido"),
    M("qkd-reuse-after-take", "qce/qkd/adapter.py", (("if k.key_id in self._seen:", "if k.key_id in self._keys:"),), "INC-0001: no reutilizar claves QKD"),
    M("qkdd-enroll-approver-off", "qce/qkd/devices.py", (("if not approved_by.strip():\n            raise PolicyViolation(\"alta de dispositivo", "if False:\n            raise PolicyViolation(\"alta de dispositivo"),), "alta con responsable"),
    M("qkdd-reapprove-approver-off", "qce/qkd/devices.py", (("if not approved_by.strip():\n            raise PolicyViolation(\"la re-aprobación", "if False:\n            raise PolicyViolation(\"la re-aprobación"),), "re-aprobación con responsable"),
    M("qkdd-retrust-auto", "qce/qkd/devices.py", (("if rec.trust_state in (\"UNTRUSTED\", \"REVIEW_REQUIRED\"):  # la identidad correcta", "if False:  # la identidad correcta"),), "sin re-confianza automática"),
    M("qkdd-identity-pin-off", "qce/qkd/devices.py", (("if pub != rec.public_key:", "if False:"),), "clave de identidad fijada"),
    M("qkdd-challenge-verify-off", "qce/qkd/devices.py", (("hybrid_verify(pub, rec.device_id.encode() + nonce, sig, CTX)", "pass"),), "desafío-respuesta"),
    M("qkdd-firmware-review-off", "qce/qkd/devices.py", (("if new_firmware != r.firmware_version:", "if False:"),), "firmware nuevo exige revisión"),
    M("qkdd-reenroll-off", "qce/qkd/devices.py", (("if device_id in self._d:", "if False:"),), "sin re-alta silenciosa"),
    M('dev-pinned-compare-off', 'qce/qkd/devices.py', (('if not hmac.compare_digest(bytes(got), rec.public_key):', 'if False:'),), 'registro: huella fijada'),
    M('dev-pinned-state-skipped', 'qce/qkd/devices.py', (('        if rec.trust_state in ("UNTRUSTED", "REVIEW_REQUIRED"):\n            raise QKDDeviceError(ErrorCategory.DEVICE_UNTRUSTED, f"estado {rec.trust_state}: requiere aprobación humana (approve)")\n        got =', '        got ='),), 'registro: sin re-confianza automática (certificado)'),
    M('dev-pinned-no-trust', 'qce/qkd/devices.py', (('        rec.trust_state, rec.last_successful_check = "TRUSTED", self._clock()\n        self._log("auth_ok", rec.device_id)\n\n    def approve', '        self._log("auth_ok", rec.device_id)\n\n    def approve'),), 'registro: la autenticación por certificado confía'),
    M('dev-pinned-mismatch-not-untrusted', 'qce/qkd/devices.py', (('            rec.trust_state = "UNTRUSTED"\n            self._log("identity_changed", rec.device_id)\n            raise QKDDeviceError(ErrorCategory.DEVICE_UNTRUSTED, "el certificado', '            self._log("identity_changed", rec.device_id)\n            raise QKDDeviceError(ErrorCategory.DEVICE_UNTRUSTED, "el certificado'),), 'registro: certificado distinto = no confiable'),
    M("qkdc-secret-repr", "qce/qkd/contract.py", (('return "<KeyMaterial [REDACTED]>"', 'return "<KeyMaterial %s>" % self._b.hex()'),), "secreto fuera de repr"),
    M("qil-store-reserve-ignores-reservation", "qce/qkd/sources.py", (("if kid in self._reserved or kid not in self._keys:", "if kid not in self._keys:"),), "QIL1: reserva exclusiva"),
    M("qil-store-commit-keeps-key", "qce/qkd/sources.py", (("            self._keys.pop(bytes(key_id), None)\n            self._reserved.discard(bytes(key_id))", "            self._reserved.discard(bytes(key_id))"),), "QIL1: consumo único (almacén)"),
    M("qil-broker-source-nonascii-uncaught", "qce/qkd/sources.py", (("PolicyViolation, UnicodeDecodeError):\n            return None", "PolicyViolation):\n            return None"),), "QIL1: broker, id no ASCII"),
    M("qil-broker-source-policy-uncaught", "qce/qkd/sources.py", (("QKDAnomaly, PolicyViolation, UnicodeDecodeError)", "QKDAnomaly, UnicodeDecodeError)"),), "QIL1: broker, consumidor no autorizado"),
    M("qil-broker-source-anomaly-uncaught", "qce/qkd/sources.py", (("except (QKDDeviceError, QKDAnomaly, PolicyViolation", "except (QKDDeviceError, PolicyViolation"),), "QIL1: broker, enlace en cuarentena"),
    M("qil-broker-source-device-error-uncaught", "qce/qkd/sources.py", (("except (QKDDeviceError, QKDAnomaly,", "except (QKDAnomaly,"),), "QIL1: broker, error de dispositivo"),
    M("qil-broker-source-release-noop", "qce/qkd/sources.py", (("        self._b.release(key_id.decode(\"ascii\"), self._consumer)", "        pass"),), "QIL1: el broker recupera la clave si el apretón falla"),
]
