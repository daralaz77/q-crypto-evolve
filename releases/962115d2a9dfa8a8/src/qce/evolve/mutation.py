"""Pruebas de mutación sobre código crítico: ¿las pruebas detectan un control de seguridad roto?

Cada mutante rompe a propósito UNA garantía. Si las pruebas siguen en verde, hay una laguna
real en la batería (mutante superviviente). Los mutantes equivalentes (no cambian el
comportamiento observable) se declaran explícitamente con su justificación; no se ocultan.
"""
from __future__ import annotations

import shutil
from concurrent.futures import ThreadPoolExecutor
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
    M("replay-never-recorded", "qce/symmetric/aead.py", (("            self._window.accept(seq)\n            return pt", "            return pt"),), "anti-repetición"),
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
    M("hs-no-forward-secrecy", "qce/protocols/session.py", (("kem, self._kem = self._kem, None  # la clave efímera se descarta pase lo que pase: secreto hacia adelante", "kem = self._kem"),), "secreto hacia adelante"),
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
    M("vault-kdf-floor-off", "qce/key_management/vault.py", (("n < 2**14 or n > 2**17 or n & (n - 1)", "n > 2**17 or n & (n - 1)"),), "parámetros KDF no degradables"),
    M("vault-kdf-ceiling-off", "qce/key_management/vault.py", (("n < 2**14 or n > 2**17 or n & (n - 1)", "n < 2**14 or n & (n - 1)"),), "KDF no inflable (DoS)"),
    M("vault-kdf-pow2-off", "qce/key_management/vault.py", (("n < 2**14 or n > 2**17 or n & (n - 1)", "n < 2**14 or n > 2**17"),), "n potencia de 2"),
    M("CANARY-noop", "qce/symmetric/aead.py", (("if seq in self._seen:", "if (seq in self._seen):"),), "canario: un mutante sin efecto DEBE sobrevivir", "canary"),
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
    M("qkdb-quarantine-not-sticky", "qce/qkd/broker.py", (("if link_id in self._link_blocked:", "if False:"),), "cuarentena persistente"),
    M("qkdb-duplicate-key-id-off", "qce/qkd/broker.py", (("if ref.key_reference in self._refs:\n                mat.destroy()", "if False:\n                mat.destroy()"),), "key_ID único"),
    M("qkdb-integrity-off", "qce/qkd/broker.py", (("if not ref.integrity_ok:", "if False:"),), "integridad de clave"),
    M("qkdb-expiry-off", "qce/qkd/broker.py", (("self._clock() >= ref.expires_at", "False"),), "caducidad de clave"),
    M("qkdb-response-shape-off", "qce/qkd/broker.py", (("if not (isinstance(res, tuple) and len(res) == 2 and isinstance(res[0], KeyReference) and isinstance(res[1], KeyMaterial)):", "if False:"),), "validación de respuesta"),
    M("prof-qber-range-off", "qce/qkd/profiles.py", (("if not _num(q) or not 0.0 <= q <= 0.5:", "if False:"),), "QBER físicamente válido"),
    M("qkdd-enroll-approver-off", "qce/qkd/devices.py", (("if not approved_by.strip():\n            raise PolicyViolation(\"alta de dispositivo", "if False:\n            raise PolicyViolation(\"alta de dispositivo"),), "alta con responsable"),
    M("qkdd-reapprove-approver-off", "qce/qkd/devices.py", (("if not approved_by.strip():\n            raise PolicyViolation(\"la re-aprobación", "if False:\n            raise PolicyViolation(\"la re-aprobación"),), "re-aprobación con responsable"),
    M("qkdd-retrust-auto", "qce/qkd/devices.py", (("if rec.trust_state in (\"UNTRUSTED\", \"REVIEW_REQUIRED\"):", "if False:"),), "sin re-confianza automática"),
    M("rel-path-check-off", "qce/recovery/release.py", (("if os.path.isabs(rel_path) or rel_path != os.path.normpath(rel_path) or rel_path.startswith(\"..\"):", "if False:"),), "rutas del manifiesto",
      "defensa en profundidad: la comprobación resolve() posterior y el hash del snapshot rechazan las mismas rutas; ninguna variante maliciosa llega a escribir"),
    M("rel-rollback-scope-off", "qce/recovery/release.py", (("if rel.startswith(ROLLBACK_ALLOWED):", "if True:"),), "la reversión no toca evidencia/umbrales"),
    M("rel-stable-signature-off", "qce/recovery/release.py", (("if not approver or approver not in approvals.valid_statements(root, release_id, \"approver\"):", "if not approver:"),), "STABLE firmado"),
    M("rel-downgrade-off", "qce/recovery/release.py", (("if new_seq < old_seq:", "if False:"),), "sin downgrade de STABLE"),
    M("trust-key-unique-off", "qce/evolve/approvals.py", (("if e[\"public_key\"] == public_bytes.hex() and other != identity:", "if False:"),), "una clave = una identidad"),
    M("trust-veto-off", "qce/evolve/approvals.py", (("if not reg_p.exists() or has_valid_veto(root, release_id, role):", "if not reg_p.exists():"),), "veto de reject"),
    M("wf-resume-shortcut", "qce/evolve/workflow.py", (("allowed.add(t[\"resume_to\"])  # solo se vuelve a donde se estaba", "allowed.add(\"INDEPENDENT_REVIEW\")"),), "sin atajo desde REVIEW_REQUIRED"),
    M("wf-findings-erasable", "qce/evolve/workflow.py", (("findings = sorted(set(t[\"blocking_findings\"]) | set(blocking_findings or []))", "findings = sorted(set(blocking_findings or []))"),), "hallazgos no borrables"),
    M("wf-approval-unverified", "qce/evolve/workflow.py", (("if self._verify_approval is None or not refs or not all(self._verify_approval(r) for r in refs):", "if False:"),), "aprobación verificable"),
    M("wf-log-verify-off", "qce/evolve/workflow.py", (("        self.log.verify()  # el estado se reconstruye solo desde un registro íntegro\n", ""),), "registro íntegro"),
    M("gate-ratchet-off", "qce/evolve/gates.py", (("if weaker:\n                problems.append(f\"umbral", "if False:\n                problems.append(f\"umbral"),), "trinquete"),
    M("gate-ratchet-merge-off", "qce/evolve/gates.py", (("\"thresholds\": merged,", "\"thresholds\": th,"),), "historial solo endurece"),
    M("gate-zero-tests-ok", "qce/evolve/gates.py", (("if rc != 0 or passed_n < 1:", "if rc != 0:"),), "0 pruebas ≠ superada"),
    M("gate-bootfile-off", "qce/evolve/gates.py", (("if (root / boot).exists():", "if False:"),), "sin conftest raíz"),
    M("ledger-open-validate-off", "qce/learning/ledger.py", (("or inc.confidence == \"CONFIRMADA\":", "or False:"),), "incidente no nace confirmado"),
    M("ledger-testref-off", "qce/learning/ledger.py", (("if not TEST_REF.match(ref) or \"..\" in ref:", "if False:"),), "sin inyección de pytest"),
    M("hs-failed-state-off", "qce/protocols/session.py", (("self._state = \"failed\"  # un único intento", "self._state = \"sent_hello\"  # un único intento"),), "handshake cierra al fallar"),
    M("ks-rotate-state-off", "qce/key_management/keystore.py", (("if old.state is not State.ACTIVE:  # antes de crear nada", "if False:  # antes de crear nada"),), "rotate sin huérfanos"),
    M("chain-lock-off", "qce/core/chainlog.py", (("fcntl.flock(lk, fcntl.LOCK_EX)", "pass"),), "cadena concurrente"),
    M("scan-fromimport-off", "qce/security/scanners.py", (("if node.module == \"random\":", "if False:"),), "escáner from-import"),
    M("prof-tsirelson-off", "qce/qkd/profiles.py", (("s > TSIRELSON + 1e-9", "s > TSIRELSON + 1.0"),), "cota de Tsirelson"),
    M("prof-chsh-margin-boundary", "qce/qkd/profiles.py", (("elif s <= CLASSICAL_CHSH + policy.chsh_margin:", "elif s < CLASSICAL_CHSH + policy.chsh_margin:"),), "CHSH inclusivo"),
    M("prof-chsh-off", "qce/qkd/profiles.py", (("elif s <= CLASSICAL_CHSH + policy.chsh_margin:", "elif False:"),), "Bell/CHSH"),
    M("prof-pa-off", "qce/qkd/profiles.py", (("if evidence[\"privacy_amplification\"] is not True:", "if False:"),), "amplificación de privacidad"),
    M("prof-epsilon-off", "qce/qkd/profiles.py", (("elif eps > policy.max_epsilon:", "elif False:"),), "clave finita ε"),
    M("prof-hops-off", "qce/qkd/profiles.py", (("elif hops > policy.max_trusted_hops:", "elif False:"),), "saltos de confianza"),
    M("prof-relay-off", "qce/qkd/profiles.py", (("evidence.get(\"relay_holds_key\") is not False", "False"),), "relé MDI no confiable"),
    M("prof-decoy-off", "qce/qkd/profiles.py", (("evidence[\"decoy_ok\"] is not True", "False"),), "estados señuelo"),
    M("prof-spec-required-off", "qce/qkd/profiles.py", (("if not spec or not _num(spec.get(need)):", "if False:"),), "ficha aprobada"),
    M("prof-phase-off", "qce/qkd/profiles.py", (("elif pe > spec[\"phase_error_max\"]:", "elif False:"),), "error de fase TF"),
    M("prof-calibration-off", "qce/qkd/profiles.py", (("if evidence[\"shot_noise_calibrated\"] is not True:", "if False:"),), "calibración CV"),
    M("prof-excess-noise-off", "qce/qkd/profiles.py", (("elif spec and _num(spec.get(\"excess_noise_max\")) and xi > spec[\"excess_noise_max\"]:", "elif False:"),), "ruido en exceso CV"),
    M("prof-loophole-off", "qce/qkd/profiles.py", (("if \"loophole_free\" in profile.witnesses and evidence[\"loophole_free\"] is not True:", "if False:"),), "DI sin lagunas"),
    M("prof-missing-witness-off", "qce/qkd/profiles.py", (("    if missing:\n", "    if False:\n"),), "testigos ausentes"),
    M("prof-assurance-eval-off", "qce/qkd/profiles.py", (("if profile.assurance < Assurance(policy.min_assurance) or profile.assurance == Assurance.NONE:", "if False:"),), "garantía mínima"),
    M("prof-qber-off", "qce/qkd/profiles.py", (("elif q >= policy.qber_abort:", "elif False:"),), "QBER en perfiles"),
    M("prof-keybinding-off", "qce/qkd/profiles.py", (("if key_id is not None and evidence[\"key_id\"] != key_id:", "if False:"),), "testigos ligados a clave",
      "el broker aplica el mismo enlace tras adquirir (qkdb-witness-binding-off); la comprobación en evaluate() es redundante"),
    M("qkdb-assurance-attach-off", "qce/qkd/broker.py", (("if prof.assurance < profiles.Assurance(self.policy.min_assurance) or prof.assurance == profiles.Assurance.NONE:", "if False:"),), "garantía mínima en alta"),
    M("qkdb-witness-binding-off", "qce/qkd/broker.py", (("if evidence.get(\"key_id\") != ref.key_reference:", "if False:"),), "testigos de otra clave"),
    M("qkdb-witness-anomaly-off", "qce/qkd/broker.py", (("if any(f.kind == \"anomaly\" for f in findings):", "if False:"),), "anomalía → cuarentena"),
    M("qkdb-witness-invalid-off", "qce/qkd/broker.py", (("if any(f.kind == \"invalid\" for f in findings):", "if False:"),), "inválido → rechazo"),

    M("qkdd-identity-pin-off", "qce/qkd/devices.py", (("if pub != rec.public_key:", "if False:"),), "clave de identidad fijada"),
    M("qkdd-challenge-verify-off", "qce/qkd/devices.py", (("hybrid_verify(pub, rec.device_id.encode() + nonce, sig, CTX)", "pass"),), "desafío-respuesta"),
    M("qkdd-firmware-review-off", "qce/qkd/devices.py", (("if new_firmware != r.firmware_version:", "if False:"),), "firmware nuevo exige revisión"),
    M("qkdd-reenroll-off", "qce/qkd/devices.py", (("if device_id in self._d:", "if False:"),), "sin re-alta silenciosa"),
    M("qkdc-secret-repr", "qce/qkd/contract.py", (('return "<KeyMaterial [REDACTED]>"', 'return "<KeyMaterial %s>" % self._b.hex()'),), "secreto fuera de repr"),
]


SANDBOX_FILES = ("pytest.ini", "THREAT_MODEL.md", "LIMITATIONS.md", "gates.json", "requirements.lock")


def _sandbox(root: Path, work: Path) -> None:
    shutil.copytree(root / "qce", work / "qce", ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copytree(root / "tests", work / "tests", ignore=shutil.ignore_patterns("__pycache__"))
    for f in SANDBOX_FILES:
        if (root / f).exists():
            shutil.copy2(root / f, work / f)


def _pytest(work: Path, timeout: int) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-m", "pytest", "-x", "-q", "-p", "no:cacheprovider"], cwd=work,
                          capture_output=True, text=True, timeout=timeout,
                          env={"PYTHONPATH": str(work), "PATH": "/usr/bin:/bin", "HYPOTHESIS_STORAGE_DIRECTORY": str(work / ".h")})


WORKERS = 6


def _run_one(root: Path, m: Mutant, timeout: int) -> dict:
    with tempfile.TemporaryDirectory() as td:
        work = Path(td)
        _sandbox(root, work)
        f = work / m.path
        src = f.read_text()
        for old, new in m.edits:
            if src.count(old) != 1:
                raise RuntimeError(f"mutante {m.name}: el fragmento original aparece {src.count(old)} veces")
            src = src.replace(old, new)
        f.write_text(src)
        t1 = time.time()
        try:
            r = _pytest(work, timeout)
            if r.returncode not in (0, 1):  # 2+ = error de colección/uso: NO es una detección
                raise RuntimeError(f"mutante {m.name}: pytest devolvió {r.returncode} (no es un fallo de prueba)")
            killed = r.returncode == 1
        except subprocess.TimeoutExpired:
            killed = True  # un bucle infinito provocado por el mutante también es detección
        return {"name": m.name, "guarantee": m.guarantee, "killed": killed,
                "equivalent": bool(m.equivalent_reason), "seconds": round(time.time() - t1, 2)}


def run_mutants(root: Path, only: list[str] | None = None, timeout: int = 120) -> dict:
    t0 = time.time()
    # La línea base DEBE ser verde en el sandbox; si no, "todo mutante muere" sería un falso positivo (hallazgo 1 de la auditoría).
    with tempfile.TemporaryDirectory() as td:
        _sandbox(root, Path(td))
        base = _pytest(Path(td), timeout)
        if base.returncode != 0:
            raise RuntimeError("línea base del sandbox NO es verde; la mutación no es válida:\n" + (base.stdout + base.stderr)[-500:])
    todo = [m for m in MUTANTS if not only or m.name in only]
    stale = [m.name for m in todo for old, _ in m.edits if (root / m.path).read_text().count(old) != 1]
    if stale:  # falla rápido y claro: un mutante obsoleto no puede contarse como detección ni como superviviente
        raise RuntimeError(f"mutantes con fragmento obsoleto (el código cambió): {stale}")
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:  # cada mutante vive en su propio directorio temporal
        results = list(pool.map(lambda m: _run_one(root, m, timeout), todo))
    canary = next((r for r in results if r["name"].startswith("CANARY")), None)
    if canary and canary["killed"]:
        raise RuntimeError("el mutante canario (sin efecto) fue 'detectado': el arnés de mutación NO es fiable")
    results = [r for r in results if not r["name"].startswith("CANARY")] + ([canary] if canary else [])
    scored = [r for r in results if not r["equivalent"]]
    killed = sum(r["killed"] for r in scored)
    return {"total": len(results), "scored": len(scored), "killed": killed,
            "score": round(killed / len(scored), 4) if scored else 1.0,
            "survivors": [r["name"] for r in scored if not r["killed"]],
            "declared_equivalent": [r["name"] for r in results if r["equivalent"]],
            "seconds": round(time.time() - t0, 1), "detail": results}
