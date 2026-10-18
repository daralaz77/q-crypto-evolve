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
    M("chain-anchor-off", "qce/core/chainlog.py", (("if expected_head is not None and prev != expected_head:\n            raise IntegrityError(\"la cabeza", "if False:\n            raise IntegrityError(\"la cabeza"),), "ancla externa"),
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
    M("rel-rollback-scope-off", "qce/recovery/release.py", (("if rel.startswith(ROLLBACK_ALLOWED):  # sin symlinks ni '..' (comprobado arriba) el destino real == rel", "if True:  # sin symlinks ni '..' (comprobado arriba) el destino real == rel"),), "la reversión no toca evidencia/umbrales"),
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
    M("cust-keystore-checks-bypassed", "qce/transport/custody.py", (('der = self._store.use(key_id, Purpose.TLS, op)  # estado, caducidad y propósito los decide el KeyStore', 'der = bytes(self._store.info(key_id).secret or b"")'),), "custodia: estado/caducidad/propósito"),
    M("cust-swapped-cert-undetected", "qce/transport/custody.py", (('        if cert.public_key().public_bytes(serialization.Encoding.DER, pub) != key.public_key().public_bytes(serialization.Encoding.DER, pub):\n            raise CertificateRejected("el certificado instalado no corresponde a la clave (archivo manipulado)")', '        if False:\n            raise CertificateRejected("el certificado instalado no corresponde a la clave (archivo manipulado)")'),), "custodia: certificado = clave (uso)"),
    M("cust-install-key-match-off", "qce/transport/custody.py", (('        if cert.public_key().public_bytes(serialization.Encoding.DER, pub) != key.public_key().public_bytes(serialization.Encoding.DER, pub):\n            raise CertificateRejected("el certificado no corresponde a la clave custodiada")', '        if False:\n            raise CertificateRejected("el certificado no corresponde a la clave custodiada")'),), "custodia: certificado = clave (instalación)"),
    M("cust-install-validity-off", "qce/transport/custody.py", (('if not cert.not_valid_before_utc <= now <= cert.not_valid_after_utc:', 'if False:'),), "custodia: vigencia del certificado"),
    M("cust-install-name-off", "qce/transport/custody.py", (('        if name not in names:', '        if False:'),), "custodia: nombre del certificado"),
    M("cust-rotation-keeps-old-active", "qce/transport/custody.py", (('        self._store.retire(old)', '        pass'),), "custodia: rotación retira la anterior"),
    M("cust-revoke-keeps-serving", "qce/transport/custody.py", (('        if server is not None:\n            server.stop_accepting()', '        if False:\n            server.stop_accepting()'),), "custodia: revocación detiene conexiones nuevas"),
    M("cust-plaintext-temp-key", "qce/transport/custody.py", (('serialization.BestAvailableEncryption(password)', 'serialization.NoEncryption()'),), "custodia: clave temporal cifrada"),
    M("cust-no-certificate-needed", "qce/transport/custody.py", (('        if not cert_path.exists():\n            raise CertificateRejected("la clave no tiene certificado instalado")', '        if False:\n            raise CertificateRejected("la clave no tiene certificado instalado")'),), "custodia: sin certificado no se sirve"),
    M("tls-key-password-dropped", "qce/transport/tls13.py", (('ctx.load_cert_chain(str(certfile), str(keyfile), password=key_password)', 'ctx.load_cert_chain(str(certfile), str(keyfile))'),), "transporte: clave cifrada"),
    M("tls-server-stop-accepting-noop", "qce/transport/tls13.py", (('    def stop_accepting(self) -> None:\n        """Revocación: ninguna conexión nueva se atiende (las abiertas deben cerrarse por quien revoca)."""\n        self._ctx = None', '    def stop_accepting(self) -> None:\n        """Revocación: ninguna conexión nueva se atiende (las abiertas deben cerrarse por quien revoca)."""\n        pass'),), "transporte: parada de conexiones nuevas"),
    M("tls-client-min-version-off", "qce/transport/tls13.py", (('    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)  # check_hostname=True y CERT_REQUIRED por defecto\n    ctx.minimum_version = ssl.TLSVersion.TLSv1_3\n', '    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)  # check_hostname=True y CERT_REQUIRED por defecto\n'),), "TLS 1.3 mínimo (cliente)"),
    M("tls-server-min-version-off", "qce/transport/tls13.py", (('    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)\n    ctx.minimum_version = ssl.TLSVersion.TLSv1_3\n', '    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)\n'),), "TLS 1.3 mínimo (servidor)"),
    M("tls-client-verify-off", "qce/transport/tls13.py", (('    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)  # check_hostname=True y CERT_REQUIRED por defecto\n', '    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)  # check_hostname=True y CERT_REQUIRED por defecto\n    ctx.check_hostname = False\n    ctx.verify_mode = ssl.CERT_NONE\n'),), "verificación de certificado"),
    M("tls-tickets-on", "qce/transport/tls13.py", (('    ctx.num_tickets = 0  # sin reanudación de sesión: cada conexión hace un apretón completo y fresco\n', ''),), "sin reanudación"),
    M("tls-attestation-skipped", "qce/transport/tls13.py", (('        _export_config()\n        _attest()\n        _attested = True', '        _export_config()\n        _attested = True'),), "atestación obligatoria"),
    M("tls-attestation-ignores-failures", "qce/transport/tls13.py", (('    bad = [msg for msg, got, want in checks if got != want]', '    bad = []'),), "atestación efectiva"),
    M("tls-mtls-off", "qce/transport/tls13.py", (('        ctx.verify_mode = ssl.CERT_REQUIRED\n        ctx.load_verify_locations(str(client_ca))', '        ctx.load_verify_locations(str(client_ca))'),), "autenticación mutua"),
    M("tls-frame-limit-off", "qce/transport/tls13.py", (('    if n > max_size:\n', '    if False:\n'),), "límite de mensaje"),
    M("tls-config-allows-x25519", "qce/transport/tls13.py", (('Groups = {HYBRID_GROUP}\n', 'Groups = X25519:{HYBRID_GROUP}\n'),), "grupo híbrido único"),
    M("tls-config-allows-tls12", "qce/transport/tls13.py", (('MinProtocol = TLSv1.3\n', 'MinProtocol = TLSv1.2\n'),), "TLS 1.3 por configuración", "Python fija su propio mínimo (TLS 1.2) al crear el contexto y sobrescribe MinProtocol; TLS 1.2 queda bloqueado igualmente por el grupo híbrido único y por minimum_version en nuestros contextos (defensa en profundidad para otros clientes de la misma configuración)"),
    M("conf-server-mac-truncated", "qce/protocols/session.py", (('if not ct_equal(mac_c, mac(ck, b"client" + th)):', 'if not ct_equal(mac_c[:16], mac(ck, b"client" + th)[:16]):'),), "conformidad: MAC completo"),
    M("conf-client-mac-truncated", "qce/protocols/session.py", (('if not ct_equal(mac_s, mac(self._ck, b"server" + self._th + self._mac_c)):', 'if not ct_equal(mac_s[:16], mac(self._ck, b"server" + self._th + self._mac_c)[:16]):'),), "conformidad: MAC completo"),
    M("conf-fingerprint-dropped-client", "qce/protocols/session.py", (('signed = _h(self._m1, suite_b, nonce_s, kem_pk, fingerprint(self._pinned))', 'signed = _h(self._m1, suite_b, nonce_s, kem_pk)'),), "conformidad: huella en lo firmado"),
    M("conf-ct-not-in-transcript-server", "qce/protocols/session.py", (('th = _h(self._m1, self._m2, ct)\n        c2s, s2c, ck = _derive(secret, th)', 'th = _h(self._m1, self._m2)\n        c2s, s2c, ck = _derive(secret, th)'),), "conformidad: ct en el transcript"),
    M("rel-id-binding-off", "qce/recovery/release.py", (('if release_id != expected or m.get("release_id") != expected:', 'if False:'),), "id ligado al contenido"),
    M("rel-symlink-tree-off", "qce/recovery/release.py", (('raise IntegrityError(f"symlink no permitido en el árbol versionado: {p.relative_to(root)}")', 'pass'),), "sin symlinks en el árbol"),
    M("rel-rollback-symlink-off", "qce/recovery/release.py", (('if src.is_symlink() or _has_symlink(root, rel):  # OJO: dst ya está resuelto; hay que mirar la ruta SIN resolver', 'if False:'),), "reversión sin symlinks"),
    M("gate-purge-bytecode-off", "qce/evolve/gates.py", (('    _purge_bytecode(root)\n    r = subprocess.run(', '    r = subprocess.run('),), "sin .pyc plantados"),
    M("wf-create-state-forced-off", "qce/evolve/workflow.py", (('clean = asdict(task) | {"final_state": "CREATED",', 'clean = asdict(task) | {"final_state": task.final_state,'),), "estado inicial CREATED"),
    M("wf-expected-head-off", "qce/evolve/workflow.py", (('self.log.append(rec, expected_head=head)', 'self.log.append(rec)'),), "concurrencia optimista"),
    M("wf-norm-off", "qce/evolve/workflow.py", (('return unicodedata.normalize("NFKC", actor).strip().casefold()', 'return actor'),), "identidad normalizada"),
    M("wf-all-implementers-off", "qce/evolve/workflow.py", (('implementers = set(t["implementer_ids"]) | (', 'implementers = set() | ('),), "todo autor es excluido"),
    M("wf-id-pattern-off", "qce/evolve/workflow.py", (('if not ID_OK.match(task.task_id):', 'if False:'),), "ids estructurales seguros"),
    M("thr-validate-off", "qce/evolve/gates.py", (('if not ok:\n            raise QCEError(f"umbral', 'if False:\n            raise QCEError(f"umbral'),), "umbrales finitos"),
    M("thr-nan-baseline-off", "qce/evolve/gates.py", (('if not isinstance(v, (int, float)) or isinstance(v, bool) or v != v:\n                continue', 'if False:\n                continue'),), "sin NaN en baseline"),
    M("g3-canary-required-off", "qce/evolve/gates.py", (('if not m.get("canary_ok"):', 'if False:'),), "canario exigido"),
    M("g3-min-mutants-off", "qce/evolve/gates.py", (('if m["scored"] < th["min_mutants"]:', 'if False:'),), "mínimo de mutantes"),
    M("g3-equiv-cap-off", "qce/evolve/gates.py", (('if len(m["declared_equivalent"]) > th["max_declared_equivalent"]:', 'if False:'),), "tope de equivalentes"),
    M("g4-resolved-no-test-off", "qce/evolve/gates.py", (('if inc.get("status") == "resuelto" and not inc.get("reproduction_test"):', 'if False:'),), "resuelto exige prueba"),
    M("ledger-clear-test-off", "qce/learning/ledger.py", (('if not changes["reproduction_test"]:', 'if False:'),), "no vaciar prueba"),
    M("ledger-severity-lower-off", "qce/learning/ledger.py", (('if SEVERITIES.index(changes["severity"]) < SEVERITIES.index(cur.get("severity", "media")) and "approver" not in changes:', 'if False:'),), "no rebajar severidad"),
    M("appr-casefold-off", "qce/evolve/approvals.py", (('if other != identity and unicodedata.normalize("NFKC", other).casefold() == identity.casefold():', 'if False:'),), "identidades sin colisión"),
    M("appr-role-change-off", "qce/evolve/approvals.py", (('if identity in data and data[identity]["role"] != role:', 'if False:'),), "sin cambio de rol"),
    M("appr-filename-verdict-off", "qce/evolve/approvals.py", (('[:16]}.{verdict}.json"', '[:16]}.json"'),), "accept no pisa reject"),
    M("appr-junk-off", "qce/evolve/approvals.py", (('except (ValueError, OSError, AttributeError):', 'except OSError:'),), "ficheros basura"),
    M("brk-normalize-off", "qce/qkd/broker.py", (('ref = self._normalize(ref, ad, link_id)', 'ref = ref'),), "metadatos propios del broker"),
    M("brk-spec-from-device", "qce/qkd/broker.py", (('self._caps[link_id] = (protocol, rec.spec, bool(caps.is_simulation))', 'self._caps[link_id] = (protocol, caps.spec, bool(caps.is_simulation))'),), "ficha del alta humano"),
    M("brk-protocol-pin-off", "qce/qkd/broker.py", (('if rec.protocol and caps.qkd_protocol != rec.protocol:', 'if False:'),), "protocolo fijado"),
    M("brk-witness-dict-off", "qce/qkd/broker.py", (('if not isinstance(w, dict):', 'if False:'),), "testigos tipados"),
    M("brk-ttl-clamp-off", "qce/qkd/broker.py", (('expires = min(ref.expires_at, now + self.policy.max_key_ttl_s)', 'expires = ref.expires_at'),), "tope de TTL"),
    M("brk-already-expired-off", "qce/qkd/broker.py", (('if expires <= now:', 'if False:'),), "clave caducada al llegar"),
    M("san-key-name-off", "qce/core/chainlog.py", (('if _SENSITIVE_KEY.search(str(k)) and isinstance(v, (str, bytes, bytearray)):', 'if False:'),), "redacción por nombre de campo"),
    M("san-b64-short-off", "qce/core/chainlog.py", (("return len(tok) >= 22 and classes >= 2", "return len(tok) >= 40 and classes >= 2"),), "base64 corto"),
    M("san-alnum-off", "qce/core/chainlog.py", (('return bool(re.search(r"[0-9]", tok) and re.search(r"[A-Za-z]", tok)) and _entropy(tok) >= 3.5', 'return False'),), "tokens alfanuméricos"),
    M("mut-only-unknown-off", "qce/evolve/mutation.py", (('        if unknown:\n', '        if False:\n'),), "only desconocido falla"),
    M("chain-expected-head-off", "qce/core/chainlog.py", (('if expected_head is not None and prev != expected_head:  # concurrencia optimista: leer-validar-escribir atómico', 'if False:'),), "concurrencia optimista (log)"),
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

    # --- QIL1: capa interna con clave QKD (NO REVISADA) ---
    M("qil-th-bind-off", "qce/transport/qkd_layer.py", (("_lp(TH_LABEL) + _lp(bind) + ", "_lp(TH_LABEL) + "),), "QIL1: ligadura a la sesión TLS"),
    M("qil-th-cert-off", "qce/transport/qkd_layer.py", (("_lp(cert_fp) + _lp(key_id)", "_lp(key_id)"),), "QIL1: ligadura al certificado"),
    M("qil-th-kid-off", "qce/transport/qkd_layer.py", (("_lp(key_id) + _lp(nc)", "_lp(nc)"),), "QIL1: id de clave en el transcript"),
    M("qil-th-nc-off", "qce/transport/qkd_layer.py", (("_lp(nc) + _lp(ns)", "_lp(ns)"),), "QIL1: nonce del cliente en el transcript"),
    M("qil-th-ns-off", "qce/transport/qkd_layer.py", (("_lp(nc) + _lp(ns)).digest()", "_lp(nc)).digest()"),), "QIL1: nonce del servidor en el transcript"),
    M("qil-nc-constant", "qce/transport/qkd_layer.py", (("    nc = rng(NONCE_LEN)", "    nc = bytes(NONCE_LEN)"),), "QIL1: nonce del cliente fresco"),
    M("qil-ns-constant", "qce/transport/qkd_layer.py", (("    ns = rng(NONCE_LEN)", "    ns = bytes(NONCE_LEN)"),), "QIL1: nonce del servidor fresco"),
    M("qil-client-skips-server-tag", "qce/transport/qkd_layer.py", (("    if not hmac.compare_digest(ts, _mac(conf, ROLE_SERVER + th)):", "    if False:"),), "QIL1: el cliente verifica al servidor"),
    M("qil-server-skips-client-tag", "qce/transport/qkd_layer.py", (("    if not hmac.compare_digest(tc, _mac(conf, ROLE_CLIENT + th + ts)):", "    if False:"),), "QIL1: el servidor verifica al cliente"),
    M("qil-client-tag-without-ts", "qce/transport/qkd_layer.py", (("tls13.send_frame(sock, _mac(conf, ROLE_CLIENT + th + ts))", "tls13.send_frame(sock, _mac(conf, ROLE_CLIENT + th))"),), "QIL1: etiqueta del cliente cubre la del servidor"),
    M("qil-role-label-off", "qce/transport/qkd_layer.py", (("    ts = _mac(conf, ROLE_SERVER + th)", "    ts = _mac(conf, ROLE_CLIENT + th)"),), "QIL1: etiquetas con rol"),
    M("qil-tls13-not-required", "qce/transport/qkd_layer.py", (('    if sock.version() != "TLSv1.3":', "    if False:"),), "QIL1: solo sobre TLS 1.3"),
    M("qil-binding-not-required", "qce/transport/qkd_layer.py", (("    if not bind or len(bind) < BIND_MIN:", "    if False:"),), "QIL1: sin ligadura no hay capa"),
    M("qil-binding-min-boundary", "qce/transport/qkd_layer.py", (("len(bind) < BIND_MIN", "len(bind) <= BIND_MIN"),), "QIL1: mínimo de ligadura inclusivo"),
    M("qil-peer-cert-not-required", "qce/transport/qkd_layer.py", (("    if not cert:\n        raise PolicyViolation(\"no hay certificado", "    if False:\n        raise PolicyViolation(\"no hay certificado"),), "QIL1: certificado del par obligatorio"),
    M("qil-key-min-boundary", "qce/transport/qkd_layer.py", (("not QKD_KEY_MIN <= len(qkd_key)", "not QKD_KEY_MIN < len(qkd_key)"),), "QIL1: tamaño mínimo de clave inclusivo"),
    M("qil-key-max-boundary", "qce/transport/qkd_layer.py", (("<= len(qkd_key) <= QKD_KEY_MAX", "<= len(qkd_key) < QKD_KEY_MAX"),), "QIL1: tamaño máximo de clave inclusivo"),
    M("qil-server-key-range-off", "qce/transport/qkd_layer.py", (('consumida")\n    _check_key(qkd_key)', 'consumida")'),), "QIL1: el servidor valida la clave que entrega la fuente"),
    M("qil-client-key-range-off", "qce/transport/qkd_layer.py", (("    _check_key_id(key_id)\n    _check_key(qkd_key)\n    bind", "    _check_key_id(key_id)\n    bind"),), "QIL1: el cliente valida su clave"),
    M("qil-key-id-min-boundary", "qce/transport/qkd_layer.py", (("not 1 <= len(key_id) <= KEY_ID_MAX", "not 1 < len(key_id) <= KEY_ID_MAX"),), "QIL1: id mínimo inclusivo"),
    M("qil-key-id-max-boundary", "qce/transport/qkd_layer.py", (("not 1 <= len(key_id) <= KEY_ID_MAX", "not 1 <= len(key_id) < KEY_ID_MAX"),), "QIL1: id máximo inclusivo"),
    M("qil-hello-version-off", "qce/transport/qkd_layer.py", (("or data[:4] != VERSION:", "or False:"),), "QIL1: versión exacta del HELLO"),
    M("qil-hello-length-loose", "qce/transport/qkd_layer.py", (("len(data) != 5 + n + NONCE_LEN", "len(data) < 5 + n + NONCE_LEN"),), "QIL1: longitud exacta del HELLO"),
    M("qil-hello-id-bounds-off", "qce/transport/qkd_layer.py", (("if not 1 <= n <= KEY_ID_MAX or len(data)", "if len(data)"),), "QIL1: límites del id en el HELLO"),
    M("qil-accept-length-loose", "qce/transport/qkd_layer.py", (("if len(accept) != NONCE_LEN + TAG_LEN:", "if len(accept) < NONCE_LEN + TAG_LEN:"),), "QIL1: longitud exacta del ACCEPT"),
    M("qil-unknown-key-accepted", "qce/transport/qkd_layer.py", (("    if qkd_key is None:\n        raise AuthenticationFailure(\"clave QKD desconocida", "    if False:\n        raise AuthenticationFailure(\"clave QKD desconocida"),), "QIL1: clave desconocida o consumida"),
    M("qil-aad-off", "qce/transport/qkd_layer.py", (("        return REC_AAD_LABEL + self._th", "        return b\"\""),), "QIL1: AAD liga el registro a la sesión"),
    M("qil-send-counter-frozen", "qce/transport/qkd_layer.py", (("        self._n_out += 1", "        pass"),), "QIL1: contador de envío"),
    M("qil-recv-counter-frozen", "qce/transport/qkd_layer.py", (("        self._n_in += 1", "        pass"),), "QIL1: contador de recepción"),
    M("qil-write-limit-off", "qce/transport/qkd_layer.py", (("        if self._n_out >= MAX_RECORDS:", "        if False:"),), "QIL1: tope de registros (envío)"),
    M("qil-write-limit-boundary", "qce/transport/qkd_layer.py", (("        if self._n_out >= MAX_RECORDS:", "        if self._n_out > MAX_RECORDS:"),), "QIL1: tope de registros (envío) inclusivo"),
    M("qil-read-limit-off", "qce/transport/qkd_layer.py", (("        if self._n_in >= MAX_RECORDS:", "        if False:"),), "QIL1: tope de registros (recepción)"),
    M("qil-plaintext-limit-off", "qce/transport/qkd_layer.py", (("        if len(data) > MAX_PLAINTEXT:", "        if False:"),), "QIL1: tamaño máximo de registro"),
    M("qil-plaintext-limit-boundary", "qce/transport/qkd_layer.py", (("        if len(data) > MAX_PLAINTEXT:", "        if len(data) >= MAX_PLAINTEXT:"),), "QIL1: tamaño máximo de registro inclusivo"),
    M("qil-client-recv-key-wrong", "qce/transport/qkd_layer.py", (("return Layer(sock, _expand(qkd_key, th, INFO_C2S), _expand(qkd_key, th, INFO_S2C), th)", "return Layer(sock, _expand(qkd_key, th, INFO_C2S), _expand(qkd_key, th, INFO_C2S), th)"),), "QIL1: clave por dirección (cliente)"),
    M("qil-same-key-both-directions", "qce/transport/qkd_layer.py", (("return Layer(sock, _expand(qkd_key, th, INFO_C2S), _expand(qkd_key, th, INFO_S2C), th)", "return Layer(sock, _expand(qkd_key, th, INFO_C2S), _expand(qkd_key, th, INFO_C2S), th)"), ("return Layer(sock, _expand(qkd_key, th, INFO_S2C), _expand(qkd_key, th, INFO_C2S), th)", "return Layer(sock, _expand(qkd_key, th, INFO_C2S), _expand(qkd_key, th, INFO_C2S), th)")), "QIL1: una clave por dirección"),
    M("qil-one-time-keys-reusable", "qce/transport/qkd_layer.py", (("return self._keys.pop(bytes(key_id), None)", "return self._keys.get(bytes(key_id))"),), "QIL1: consumo único"),
    M("qil-broker-nonascii-uncaught", "qce/transport/qkd_layer.py", (("PolicyViolation, UnicodeDecodeError)", "PolicyViolation)"),), "QIL1: broker, id no ASCII"),
    M("qil-broker-policy-uncaught", "qce/transport/qkd_layer.py", (("QKDAnomaly, PolicyViolation, UnicodeDecodeError)", "QKDAnomaly, UnicodeDecodeError)"),), "QIL1: broker, consumidor no autorizado"),
    M("qil-broker-anomaly-uncaught", "qce/transport/qkd_layer.py", (("except (QKDDeviceError, QKDAnomaly, PolicyViolation", "except (QKDDeviceError, PolicyViolation"),), "QIL1: broker, enlace en cuarentena"),
    M("qil-broker-device-error-uncaught", "qce/transport/qkd_layer.py", (("except (QKDDeviceError, QKDAnomaly,", "except (QKDAnomaly,"),), "QIL1: broker, error de dispositivo"),
]


SANDBOX_FILES = ("pytest.ini", "THREAT_MODEL.md", "LIMITATIONS.md", "gates.json", "requirements.lock")


def _sandbox(root: Path, work: Path) -> None:
    shutil.copytree(root / "qce", work / "qce", ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copytree(root / "tests", work / "tests", ignore=shutil.ignore_patterns("__pycache__"))
    for f in SANDBOX_FILES:
        if (root / f).exists():
            shutil.copy2(root / f, work / f)
    for d in ("docs", "formal"):  # las pruebas de especificación y conformidad leen estos archivos
        if (root / d).is_dir():
            shutil.copytree(root / d, work / d, ignore=shutil.ignore_patterns("__pycache__"))


def _pytest(work: Path, timeout: int) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-B", "-m", "pytest", "-x", "-q", "-p", "no:cacheprovider"], cwd=work,
                          capture_output=True, text=True, timeout=timeout,
                          env={"PYTHONPATH": str(work), "PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1", "HYPOTHESIS_STORAGE_DIRECTORY": str(work / ".h")})


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
    if only:
        unknown = sorted(set(only) - {m.name for m in MUTANTS})
        if unknown:
            raise RuntimeError(f"mutantes desconocidos en 'only': {unknown}")
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
    return {"canary_ok": bool(canary) and not canary["killed"], "total": len(results), "scored": len(scored), "killed": killed,
            "score": round(killed / len(scored), 4) if scored else 1.0,
            "survivors": [r["name"] for r in scored if not r["killed"]],
            "declared_equivalent": [r["name"] for r in results if r["equivalent"] and not r["name"].startswith("CANARY")],
            "seconds": round(time.time() - t0, 1), "detail": results}
