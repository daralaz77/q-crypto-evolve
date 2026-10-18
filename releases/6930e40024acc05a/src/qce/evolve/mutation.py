"""Pruebas de mutación sobre código crítico: ¿las pruebas detectan un control de seguridad roto?

Cada mutante rompe a propósito UNA garantía. Si las pruebas siguen en verde, hay una laguna
real en la batería (mutante superviviente). Los mutantes equivalentes (no cambian el
comportamiento observable) se declaran explícitamente con su justificación; no se ocultan.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Mutant:
    name: str
    path: str
    edits: tuple[tuple[str, str], ...]  # (original, mutado); cada original debe aparecer
    guarantee: str
    equivalent_reason: str = ""  # no vacío = declarado equivalente


M = Mutant
MUTANTS = [
    M("replay-seen-check-off", "qce/symmetric/aead.py", (("if seq in self._seen:", "if False:"),), "anti-repetición"),
    M("replay-window-boundary", "qce/symmetric/aead.py", (("seq <= self.highest - self.size", "seq < self.highest - self.size"),), "ventana"),
    M("replay-never-recorded", "qce/symmetric/aead.py", (("        self._window.accept(seq)\n        return pt", "        return pt"),), "anti-repetición"),
    M("nonce-counter-frozen", "qce/symmetric/aead.py", (("self._next += 1", "self._next += 0"),), "unicidad de nonce"),
    M("rekey-limit-off", "qce/symmetric/aead.py", (("if self._next >= self._max:", "if False:"),), "límite por clave"),
    M("aead-key-size-off", "qce/symmetric/aead.py", (("if len(key) != 32:", "if False:"),), "256 bits"),
    M("kem-combiner-drops-ct", "qce/pqc/hybrid.py", (("_LABEL + ct + pk", "_LABEL"),), "enlace de transcript KEM"),
    M("kem-combiner-drops-x25519", "qce/pqc/hybrid.py", (("hkdf(ss_m + ss_x,", "hkdf(ss_m,"),), "hibridación (X25519)"),
    M("kem-combiner-drops-mlkem", "qce/pqc/hybrid.py", (("hkdf(ss_m + ss_x,", "hkdf(ss_x,"),), "hibridación (ML-KEM)"),
    M("sig-ed25519-skipped", "qce/pqc/hybrid.py", (("ed25519.Ed25519PublicKey.from_public_bytes(public_bytes[:32]).verify(", "(lambda *a: None)("),), "firma híbrida AND"),
    M("sig-mldsa-skipped", "qce/pqc/hybrid.py", (("mldsa.MLDSA65PublicKey.from_public_bytes(public_bytes[32:]).verify(", "(lambda *a: None)("),), "firma híbrida AND"),
    M("sig-context-ignored", "qce/pqc/hybrid.py", (("signature[ED_SIG:], message, context)", "signature[ED_SIG:], message, b'')"),), "separación de dominios"),
    M("hs-server-sig-not-verified", "qce/protocols/session.py", (("hybrid_verify(self._pinned, signed, sig, CTX_SERVER)", "pass"),), "autenticación del servidor"),
    M("hs-suite-not-offered-allowed", "qce/protocols/session.py", (("if suite not in self._offered:", "if False:"),), "anti-degradación"),
    M("hs-transcript-unsigned", "qce/protocols/session.py",
      (("signed = _h(self._m1, suite_b,", "signed = _h(suite_b,"), ("signed = _h(m1, suite_b,", "signed = _h(suite_b,")), "firma cubre ClientHello"),
    M("hs-client-confirm-off", "qce/protocols/session.py", (("if not ct_equal(mac_c, mac(ck, b\"client\" + th)):", "if False:"),), "confirmación de clave"),
    M("hs-server-confirm-off", "qce/protocols/session.py", (("if not ct_equal(mac_s,", "if False and not ct_equal(mac_s,"),), "confirmación de clave"),
    M("hs-qkd-silent-downgrade", "qce/protocols/session.py", (("if self._qkd_key is None:", "if False:"),), "sin degradación QKD"),
    M("hs-no-forward-secrecy", "qce/protocols/session.py", (("        self._kem = None  # la clave efímera se descarta: secreto hacia adelante\n", ""),), "secreto hacia adelante",
      "no observable por API: la clave efímera sigue en memoria. Cubierto por revisión, no por prueba (ver LIMITATIONS.md)"),
    M("hs-direction-binding-off", "qce/protocols/session.py", (("return self.session_id + direction + aad", "return self.session_id + aad"),), "anti-reflexión",
      "las claves de cada sentido ya difieren (c2s≠s2c), así que la reflexión falla igualmente; la dirección en el AAD es defensa en profundidad"),
    M("policy-allowlist-ignored", "qce/core/policy.py", (("suite.status != \"allowed\" or suite_id not in self.allowed_suites", "suite.status != \"allowed\""),), "política"),
    M("policy-hybrid-required-off", "qce/core/policy.py", (("if \"+\" not in suite.kem or \"ML-KEM\" not in suite.kem:", "if False:"),), "KEM híbrido obligatorio"),
    M("encoding-trailing-bytes", "qce/core/encoding.py", (("if pos != len(data):", "if False:"),), "formato estricto"),
    M("encoding-length-cap", "qce/core/encoding.py", (("if ln > MAX_FIELD or pos + ln > len(data):", "if pos + ln > len(data):"),), "límite de campo"),
    M("keys-purpose-check-off", "qce/key_management/keystore.py", (("if rec.purpose is not purpose:", "if False:"),), "separación de claves"),
    M("keys-state-check-off", "qce/key_management/keystore.py", (("if rec.state is not State.ACTIVE:", "if rec.state is State.DESTROYED:"),), "solo ACTIVE produce"),
    M("keys-expiry-boundary", "qce/key_management/keystore.py", (("if self._clock() >= rec.not_after:", "if self._clock() > rec.not_after:"),), "caducidad"),
    M("keys-expiry-off", "qce/key_management/keystore.py", (("if self._clock() >= rec.not_after:", "if False:"),), "caducidad"),
    M("keys-revoked-readable", "qce/key_management/keystore.py", (("if rec.state not in (State.ACTIVE, State.RETIRED):", "if rec.state is State.DESTROYED:"),), "revocación"),
    M("keys-no-zeroize-on-revoke", "qce/key_management/keystore.py", (("if new in (State.REVOKED, State.DESTROYED):", "if new in (State.DESTROYED,):"),), "borrado"),
    M("keys-aad-ignores-generation", "qce/key_management/keystore.py", (("key_id.encode() + generation.to_bytes(4, \"big\") + aad", "key_id.encode() + aad"),), "enlace de generación",
      "la generación ya va ligada a la clave concreta (un key_id = una generación); redundancia defensiva"),
    M("vault-rollback-check-off", "qce/key_management/vault.py", (("if epoch < min_epoch:", "if False:"),), "anti-restauración"),
    M("vault-kdf-floor-off", "qce/key_management/vault.py", (("or n < 2**14 or n > 2**22", "or n > 2**22"),), "parámetros KDF no degradables"),
    M("vault-header-not-aad", "qce/key_management/vault.py", (("decrypt(nonce, data[45:], header)", "decrypt(nonce, data[45:], b'')"),), "cabecera autenticada"),
    M("chain-hash-check-off", "qce/core/chainlog.py", (("or not hmac.compare_digest(e[\"hash\"], _digest(n, e[\"ts\"], prev, e[\"body\"]))", ""),), "integridad del registro"),
    M("chain-anchor-off", "qce/core/chainlog.py", (("if expected_head is not None and prev != expected_head:", "if False:"),), "ancla externa"),
    M("qkd-sim-allowed-in-prod", "qce/qkd/adapter.py", (("if k.source == \"SIMULATION\" and not self.policy.allow_simulated_qkd:", "if False:"),), "simulación ≠ hardware"),
    M("qkd-auth-off", "qce/qkd/adapter.py", (("if not hmac.compare_digest(k.tag,", "if False and not hmac.compare_digest(k.tag,"),), "canal clásico autenticado"),
    M("qkd-qber-boundary", "qce/qkd/adapter.py", (("if k.qber >= self.policy.qber_abort:", "if k.qber > self.policy.qber_abort:"),), "umbral QBER"),
    M("qkd-qber-nan", "qce/qkd/adapter.py", (("if not 0.0 <= k.qber <= 0.5 or k.qber != k.qber:", "if False:"),), "QBER físicamente válido"),
    M("qkd-reuse-after-take", "qce/qkd/adapter.py", (("if k.key_id in self._seen:", "if k.key_id in self._keys:"),), "INC-0001: no reutilizar claves QKD"),
    M("qkdb-simulation-allowed", "qce/qkd/broker.py", (("if caps.is_simulation and not self.policy.allow_simulated_qkd:", "if False:"),), "simulación ≠ hardware (broker)"),
    M("qkdb-trust-not-rechecked", "qce/qkd/broker.py", (("if not self.registry.is_trusted(ad.device_id):  # se reevalúa en CADA operación", "if False:"),), "confianza en cada operación"),
    M("qkdb-consumer-auth-off", "qce/qkd/broker.py", (("if consumer not in self._allowed.get(link_id, set()):", "if False:"),), "consumidor autorizado"),
    M("qkdb-consume-state-off", "qce/qkd/broker.py", (("if ref.state is not KeyState.RESERVED or ref.reserved_by != consumer:", "if False:"),), "consumo único / reserva"),
    M("qkdb-reserved-by-off", "qce/qkd/broker.py", (("or ref.reserved_by != consumer:", ":"),), "reserva por consumidor"),
    M("qkdb-qber-abort-off", "qce/qkd/broker.py", (("if qber >= self.policy.qber_abort:", "if False:"),), "espionaje → cuarentena"),
    M("qkdb-quarantine-not-sticky", "qce/qkd/broker.py", (("if link_id in self._link_blocked:", "if False:"),), "cuarentena persistente"),
    M("qkdb-duplicate-key-id-off", "qce/qkd/broker.py", (("if ref.key_reference in self._refs:\n                mat.destroy()", "if False:\n                mat.destroy()"),), "key_ID único"),
    M("qkdb-integrity-off", "qce/qkd/broker.py", (("if not ref.integrity_ok:", "if False:"),), "integridad de clave"),
    M("qkdb-expiry-off", "qce/qkd/broker.py", (("self._clock() >= ref.expires_at", "False"),), "caducidad de clave"),
    M("qkdb-response-shape-off", "qce/qkd/broker.py", (("if not (isinstance(res, tuple) and len(res) == 2 and isinstance(res[0], KeyReference) and isinstance(res[1], KeyMaterial)):", "if False:"),), "validación de respuesta"),
    M("qkdb-qber-validation-off", "qce/qkd/broker.py", (("if not isinstance(qber, (int, float)) or qber != qber or not 0.0 <= qber <= 0.5:", "if False:"),), "QBER válido"),
    M("qkdd-enroll-approver-off", "qce/qkd/devices.py", (("if not approved_by.strip():", "if False:"),), "alta con responsable"),
    M("qkdd-identity-pin-off", "qce/qkd/devices.py", (("if pub != rec.public_key:", "if False:"),), "clave de identidad fijada"),
    M("qkdd-challenge-verify-off", "qce/qkd/devices.py", (("hybrid_verify(pub, rec.device_id.encode() + nonce, sig, CTX)", "pass"),), "desafío-respuesta"),
    M("qkdd-firmware-review-off", "qce/qkd/devices.py", (("if new_firmware != r.firmware_version:", "if False:"),), "firmware nuevo exige revisión"),
    M("qkdd-reenroll-off", "qce/qkd/devices.py", (("if device_id in self._d:", "if False:"),), "sin re-alta silenciosa"),
    M("qkdc-secret-repr", "qce/qkd/contract.py", (('return "<KeyMaterial [REDACTED]>"', 'return "<KeyMaterial %s>" % self._b.hex()'),), "secreto fuera de repr"),
]


def run_mutants(root: Path, only: list[str] | None = None, timeout: int = 120) -> dict:
    results, t0 = [], time.time()
    for m in MUTANTS:
        if only and m.name not in only:
            continue
        with tempfile.TemporaryDirectory() as td:
            work = Path(td)
            shutil.copytree(root / "qce", work / "qce", ignore=shutil.ignore_patterns("__pycache__"))
            shutil.copytree(root / "tests", work / "tests", ignore=shutil.ignore_patterns("__pycache__"))
            shutil.copy2(root / "pytest.ini", work / "pytest.ini")
            f = work / m.path
            src = f.read_text()
            for old, new in m.edits:
                if src.count(old) != 1:
                    raise RuntimeError(f"mutante {m.name}: el fragmento original aparece {src.count(old)} veces")
                src = src.replace(old, new)
            f.write_text(src)
            t1 = time.time()
            try:
                r = subprocess.run([sys.executable, "-m", "pytest", "-x", "-q", "-p", "no:cacheprovider"],
                                   cwd=work, capture_output=True, text=True, timeout=timeout,
                                   env={"PYTHONPATH": str(work), "PATH": "/usr/bin:/bin", "HYPOTHESIS_STORAGE_DIRECTORY": str(work / ".h")})
                killed = r.returncode != 0
            except subprocess.TimeoutExpired:
                killed = True  # un bucle infinito provocado por el mutante también es detección
            results.append({"name": m.name, "guarantee": m.guarantee, "killed": killed,
                            "equivalent": bool(m.equivalent_reason), "seconds": round(time.time() - t1, 2)})
    scored = [r for r in results if not r["equivalent"]]
    killed = sum(r["killed"] for r in scored)
    return {"total": len(results), "scored": len(scored), "killed": killed,
            "score": round(killed / len(scored), 4) if scored else 1.0,
            "survivors": [r["name"] for r in scored if not r["killed"]],
            "declared_equivalent": [r["name"] for r in results if r["equivalent"]],
            "seconds": round(time.time() - t0, 1), "detail": results}
