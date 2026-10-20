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
    M("qkdb-consume-state-off", "qce/qkd/broker.py", (("if ref.state is not KeyState.RESERVED or ref.reserved_by != consumer:\n            self._log(\"consume_denied\"", "if False:\n            self._log(\"consume_denied\""),), "consumo único / reserva"),
    M("qkdb-reserved-by-off", "qce/qkd/broker.py", (("or ref.reserved_by != consumer:\n            self._log(\"consume_denied\"", ":\n            self._log(\"consume_denied\""),), "reserva por consumidor"),
    M("qkdb-quarantine-not-sticky", "qce/qkd/broker.py", (("if link_id in self._link_blocked:", "if False:"),), "cuarentena persistente"),
    M("qkdb-duplicate-key-id-off", "qce/qkd/broker.py", (("if ref.key_reference in self._refs:\n                mat.destroy()", "if False:\n                mat.destroy()"),), "key_ID único"),
    M("qkdb-integrity-off", "qce/qkd/broker.py", (("if not ref.integrity_ok:", "if False:"),), "integridad de clave"),
    M("qkdb-expiry-off", "qce/qkd/broker.py", (("self._clock() >= ref.expires_at", "False"),), "caducidad de clave"),
    M("qkdb-response-shape-off", "qce/qkd/broker.py", (("if not (isinstance(res, tuple) and len(res) == 2 and isinstance(res[0], KeyReference) and isinstance(res[1], KeyMaterial)):", "if False:"),), "validación de respuesta"),
    M("prof-qber-range-off", "qce/qkd/profiles.py", (("if not _num(q) or not 0.0 <= q <= 0.5:", "if False:"),), "QBER físicamente válido"),
    M("qkdd-enroll-approver-off", "qce/qkd/devices.py", (("if not approved_by.strip():\n            raise PolicyViolation(\"alta de dispositivo", "if False:\n            raise PolicyViolation(\"alta de dispositivo"),), "alta con responsable"),
    M("qkdd-reapprove-approver-off", "qce/qkd/devices.py", (("if not approved_by.strip():\n            raise PolicyViolation(\"la re-aprobación", "if False:\n            raise PolicyViolation(\"la re-aprobación"),), "re-aprobación con responsable"),
    M("qkdd-retrust-auto", "qce/qkd/devices.py", (("if rec.trust_state in (\"UNTRUSTED\", \"REVIEW_REQUIRED\"):  # la identidad correcta", "if False:  # la identidad correcta"),), "sin re-confianza automática"),
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
    M("prof-pa-off", "qce/qkd/profiles.py", (("if \"privacy_amplification\" in profile.witnesses and evidence[\"privacy_amplification\"] is not True:", "if False:"),), "amplificación de privacidad"),
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
    M("prof-keybinding-off", "qce/qkd/profiles.py", (("if key_id is not None and profile.per_key_witnesses and evidence[\"key_id\"] != key_id:", "if False:"),), "testigos ligados a clave",
      "el broker aplica el mismo enlace tras adquirir (qkdb-witness-binding-off); la comprobación en evaluate() es redundante"),
    M("qkdb-assurance-attach-off", "qce/qkd/broker.py", (("if prof.assurance < profiles.Assurance(self.policy.min_assurance) or prof.assurance == profiles.Assurance.NONE:", "if False:"),), "garantía mínima en alta"),
    M("qkdb-witness-binding-off", "qce/qkd/broker.py", (("and evidence.get(\"key_id\") != ref.key_reference:", "and False:"),), "testigos de otra clave"),
    M("qkdb-witness-anomaly-off", "qce/qkd/broker.py", (("if any(f.kind == \"anomaly\" for f in findings):", "if False:"),), "anomalía → cuarentena"),
    M("qkdb-witness-invalid-off", "qce/qkd/broker.py", (("if any(f.kind == \"invalid\" for f in findings):", "if False:"),), "inválido → rechazo"),

    M("qkdd-identity-pin-off", "qce/qkd/devices.py", (("if pub != rec.public_key:", "if False:"),), "clave de identidad fijada"),
    M("qkdd-challenge-verify-off", "qce/qkd/devices.py", (("hybrid_verify(pub, rec.device_id.encode() + nonce, sig, CTX)", "pass"),), "desafío-respuesta"),
    M("qkdd-firmware-review-off", "qce/qkd/devices.py", (("if new_firmware != r.firmware_version:", "if False:"),), "firmware nuevo exige revisión"),
    M("qkdd-reenroll-off", "qce/qkd/devices.py", (("if device_id in self._d:", "if False:"),), "sin re-alta silenciosa"),
    M("qkdc-secret-repr", "qce/qkd/contract.py", (('return "<KeyMaterial [REDACTED]>"', 'return "<KeyMaterial %s>" % self._b.hex()'),), "secreto fuera de repr"),
    M('hsm-uri-prefix-off', 'qce/transport/hsm_tls.py', (('if not key_uri.startswith("pkcs11:") or "type=private" not in key_uri:', 'if False:'),), 'HSM: solo URI pkcs11:'),
    M('hsm-uri-private-type-off', 'qce/transport/hsm_tls.py', ((' or "type=private" not in key_uri:', ':'),), 'HSM: solo clave privada'),
    M('hsm-file-exists-check-off', 'qce/transport/hsm_tls.py', (('            if not Path(f).is_file():', '            if False:'),), 'HSM: archivos existentes'),
    M('hsm-extractable-check-off', 'qce/transport/hsm_tls.py', (('            if key_is_extractable(c, pkey):', '            if False:'),), 'HSM: rechazar claves exportables'),
    M('hsm-extractable-rsa-only', 'qce/transport/hsm_tls.py', (('for name in (b"d", b"priv"):', 'for name in (b"d",):'),), 'HSM: exportabilidad EC'),
    M('hsm-extractable-ec-only', 'qce/transport/hsm_tls.py', (('for name in (b"d", b"priv"):', 'for name in (b"priv",):'),), 'HSM: exportabilidad RSA'),
    M('hsm-extractable-always-false', 'qce/transport/hsm_tls.py', (('            return True\n        P._errors(crypto)', '            return False\n        P._errors(crypto)'),), 'HSM: la clave de software se detecta'),
    M('hsm-cert-match-check-off', 'qce/transport/hsm_tls.py', (('            if l.SSL_CTX_check_private_key(self._ctx) != 1:', '            if False:'),), 'HSM: certificado = clave del token'),
    M('hsm-cert-load-check-off', 'qce/transport/hsm_tls.py', (('            if l.SSL_CTX_use_certificate_chain_file(self._ctx, str(cert_file).encode()) != 1:', '            if False:'),), 'HSM: certificado válido'),
    M('hsm-no-key-check-off', 'qce/transport/hsm_tls.py', (('            if not pkey:\n                raise PolicyViolation("el token no tiene esa clave privada', '            if False:\n                raise PolicyViolation("el token no tiene esa clave privada'),), 'HSM: la clave existe'),
    M('hsm-up-ref-off', 'qce/transport/hsm_tls.py', (('        l.SSL_CTX_up_ref(self._ctx)           # cada conexión cierra SU referencia al contexto\n', ''),), 'HSM: cada conexión tiene su referencia'),
    M('hsm-attest-off', 'qce/transport/hsm_tls.py', (('            P._attest(conn, self._suite, self._group, require_psk=False)\n', '            pass\n'),), 'HSM: atestación tras el apretón'),
    M('hsm-libctx-cache-off', 'qce/transport/hsm_tls.py', (('            if key not in _LIBCTX:', '            if True:'),), 'HSM: un contexto de biblioteca por configuración'),
    M('hsm-libctx-freed-on-close', 'qce/transport/hsm_tls.py', (('        self._libctx = None   # NO se libera: el módulo PKCS#11 vive hasta el final del proceso', '        c.OSSL_LIB_CTX_free(self._libctx)\n        self._libctx = None'),), 'HSM: el módulo no se descarga (fork)'),
    M('hsm-ssl-ctx-not-freed', 'qce/transport/hsm_tls.py', (('        if self._ctx:\n            l.SSL_CTX_free(self._ctx)\n            self._ctx = None', '        if self._ctx:\n            self._ctx = None'),), 'HSM: se libera el SSL_CTX'),
    M('hsm-suite-unchecked', 'qce/transport/hsm_tls.py', (('        P._check_suite(suite)\n        P._check_group(group)\n        if not key_uri', '        P._check_group(group)\n        if not key_uri'),), 'HSM: suite permitida'),
    M('hsm-group-unchecked', 'qce/transport/hsm_tls.py', (('        P._check_group(group)\n        if not key_uri', '        if not key_uri'),), 'HSM: grupo permitido'),
    M('hsm-stored-key-type-wrong', 'qce/transport/hsm_tls.py', (('OSSL_STORE_INFO_PKEY = 4', 'OSSL_STORE_INFO_PKEY = 3'),), 'HSM: tipo de objeto clave privada'),
    M('sc-g1-check-skipped', 'qce/evolve/gates.py', (('        problems += supply_chain.check(root)   # hashes de dependencias y SBOM coherentes con el lock (sin red)\n', ''),), 'cadena de suministro: G1 la comprueba'),
    M('sc-hash-pattern-loose', 'qce/evolve/supply_chain.py', (('SHA = re.compile(r"^[0-9a-f]{64}$")', 'SHA = re.compile(r"^[0-9a-f]+$")'),), 'cadena de suministro: SHA-256 de 64 hex'),
    M('sc-missing-hashes-ignored', 'qce/evolve/supply_chain.py', (('            if name not in got:\n                problems.append(f"{name} no tiene hashes")', '            if name not in got:\n                pass'),), 'cadena de suministro: todo paquete con hashes'),
    M('sc-version-mismatch-ignored', 'qce/evolve/supply_chain.py', (('            elif got[name][0] != ver:', '            elif False:'),), 'cadena de suministro: misma versión que el lock'),
    M('sc-empty-hashes-allowed', 'qce/evolve/supply_chain.py', (('            elif not got[name][1] or not all(SHA.match(h) for h in got[name][1]):', '            elif not all(SHA.match(h) for h in got[name][1]):'),), 'cadena de suministro: al menos un hash'),
    M('sc-extra-package-allowed', 'qce/evolve/supply_chain.py', (('            if name not in lock:\n                problems.append(f"{name} tiene hashes pero no está en el lock")', '            if name not in lock:\n                pass'),), 'cadena de suministro: sin paquetes de más'),
    M('sc-sbom-mismatch-ignored', 'qce/evolve/supply_chain.py', (('        if comps != lock:', '        if False:'),), 'cadena de suministro: SBOM = lock'),
    M('sc-parser-accepts-options', 'qce/evolve/supply_chain.py', (('            if not p.startswith("--hash=sha256:"):\n                raise QCEError', '            if False:\n                raise QCEError'),), 'cadena de suministro: solo --hash=sha256'),
    M('sc-pypi-name-unvalidated', 'qce/evolve/supply_chain.py', (('    if not LOCK_LINE.match(f"{name}=={version}"):', '    if False:'),), 'cadena de suministro: nombre validado antes de armar la URL'),
    M('sc-sbom-nondeterministic', 'qce/evolve/supply_chain.py', (('uuid.uuid5(uuid.NAMESPACE_URL, json.dumps(body, sort_keys=True))', 'uuid.uuid4()'),), 'cadena de suministro: SBOM determinista'),
    M('sc-hashes-drop-wheels', 'qce/evolve/supply_chain.py', (('        hs = sorted({h for _, h in meta["files"]})', '        hs = sorted({h for f, h in meta["files"] if f.endswith(".tar.gz")}) or sorted({h for _, h in meta["files"]})[:1]'),), 'cadena de suministro: todos los archivos publicados'),
    M('sc-empty-pypi-response-accepted', 'qce/evolve/supply_chain.py', (('    if not files:\n        raise QCEError', '    if False:\n        raise QCEError'),), 'cadena de suministro: PyPI sin archivos'),
    M('psk-group-allowlist-off', 'qce/transport/tls13_psk.py', (('    if group not in GROUPS:\n        raise PolicyViolation', '    if False:\n        raise PolicyViolation'),), 'PSK: grupos permitidos'),
    M('psk-group-attest-uses-default', 'qce/transport/tls13_psk.py', (('    if conn.group != REPORTED_GROUP_NAME[group]:\n        problems.append', '    if conn.group != REPORTED_GROUP_NAME[GROUP]:\n        problems.append'),), 'PSK: se atestigua el grupo pedido'),
    M('psk-group-context-ignored', 'qce/transport/tls13_psk.py', (('groups = ctypes.create_string_buffer(group.encode())', 'groups = ctypes.create_string_buffer(GROUP.encode())'),), 'PSK: el grupo pedido llega al contexto'),
    M('psk-group-client-unchecked', 'qce/transport/tls13_psk.py', (('    _check_suite(suite)\n    _check_group(group)\n    _nodelay(sock)\n    psk = prepare_psk(qkd_key, identity)', '    _check_suite(suite)\n    _nodelay(sock)\n    psk = prepare_psk(qkd_key, identity)'),), 'PSK: el cliente valida el grupo'),
    M('psk-group-server-unchecked', 'qce/transport/tls13_psk.py', (('    _check_suite(suite)\n    _check_group(group)\n    _nodelay(sock)\n    lib = _load()', '    _check_suite(suite)\n    _nodelay(sock)\n    lib = _load()'),), 'PSK: el servidor valida el grupo'),
    M('psk-default-group-classical', 'qce/transport/tls13_psk.py', (('GROUP = "X25519MLKEM768"', 'GROUP = "X25519"'),), 'PSK: el grupo por defecto es el híbrido'),
    M('psk-groups-allow-more', 'qce/transport/tls13_psk.py', (('GROUPS = ("X25519MLKEM768", "X25519")', 'GROUPS = ("X25519MLKEM768", "X25519", "X448")'),), 'PSK: solo dos grupos permitidos'),
    M('psk-nodelay-client-off', 'qce/transport/tls13_psk.py', (('    _check_group(group)\n    _nodelay(sock)\n    psk = prepare_psk(qkd_key, identity)', '    _check_group(group)\n    psk = prepare_psk(qkd_key, identity)'),), 'PSK: TCP_NODELAY (cliente)'),
    M('psk-nodelay-server-off', 'qce/transport/tls13_psk.py', (('    _check_group(group)\n    _nodelay(sock)\n    lib = _load()', '    _check_group(group)\n    lib = _load()'),), 'PSK: TCP_NODELAY (servidor)'),
    M('cer-parse-public-path-first', 'qce/evolve/ceremony.py', (('    if not re.fullmatch(r"[0-9a-fA-F]+", text):', '    if True:'),), 'ceremonia: lo hexadecimal no es una ruta'),
    M('psk-leak-ssl-not-freed', 'qce/transport/tls13_psk.py', (('        self._l.SSL_free(self._ssl)\n', '        pass\n'),), 'PSK: se libera SSL (fugas de memoria)'),
    M('psk-leak-ctx-not-freed', 'qce/transport/tls13_psk.py', (('        self._l.SSL_CTX_free(self._ctx)\n', '        pass\n'),), 'PSK: se libera SSL_CTX (fugas de memoria)'),
    M('psk-leak-socket-not-closed', 'qce/transport/tls13_psk.py', (('        try:\n            self._sock.close()\n        except OSError:\n            pass\n        self._keep.clear()', '        self._keep.clear()'),), 'PSK: se cierra el socket (descriptores)'),
    M('slh-leak-pkey-not-freed-sign', 'qce/pqc/slhdsa.py', (('            c.EVP_MD_CTX_free(mctx)\n            c.EVP_PKEY_free(pkey)\n\n\ndef slhdsa_verify', '            c.EVP_MD_CTX_free(mctx)\n\n\ndef slhdsa_verify'),), 'SLH-DSA: se libera la clave al firmar'),
    M('slh-leak-pkey-not-freed-verify', 'qce/pqc/slhdsa.py', (('        c.EVP_MD_CTX_free(mctx)\n        c.EVP_PKEY_free(pkey)\n', '        c.EVP_MD_CTX_free(mctx)\n'),), 'SLH-DSA: se libera la clave al verificar'),
    M('cer-name-unchecked', 'qce/evolve/ceremony.py', (('if not name or "/" in name or "\\\\" in name or name.startswith(".") or len(name) > 64:', 'if False:'),), 'ceremonia: nombre de identidad'),
    M('cer-name-length-boundary', 'qce/evolve/ceremony.py', (('or len(name) > 64:', 'or len(name) >= 64:'),), 'ceremonia: nombre máximo inclusivo'),
    M('cer-key-inside-repo-allowed', 'qce/evolve/ceremony.py', (('    if _inside(out_dir, root):', '    if False:'),), 'ceremonia: clave fuera del repositorio'),
    M('cer-key-overwrite-allowed', 'qce/evolve/ceremony.py', (('os.O_WRONLY | os.O_CREAT | os.O_EXCL', 'os.O_WRONLY | os.O_CREAT | os.O_TRUNC'),), 'ceremonia: no pisa claves'),
    M('cer-key-mode-open', 'qce/evolve/ceremony.py', (('os.O_EXCL, 0o600)', 'os.O_EXCL, 0o644)'),), 'ceremonia: clave 0600'),
    M('cer-perm-check-off', 'qce/evolve/ceremony.py', (('    if mode & 0o077:', '    if False:'),), 'ceremonia: permisos de la clave'),
    M('cer-perm-check-group-only', 'qce/evolve/ceremony.py', (('    if mode & 0o077:', '    if mode & 0o070:'),), 'ceremonia: permisos de otros usuarios'),
    M('cer-seed-length-unchecked', 'qce/evolve/ceremony.py', (('    if len(text) != SEED_HEX_LEN:', '    if False:'),), 'ceremonia: formato de la clave'),
    M('cer-public-length-unchecked', 'qce/evolve/ceremony.py', (('    if len(pub) != SIG_PK_LEN:', '    if False:'),), 'ceremonia: longitud de la pública'),
    M('cer-register-any-role', 'qce/evolve/ceremony.py', (('    if role not in ("reviewer", "approver"):', '    if False:'),), 'ceremonia: solo reviewer/approver'),
    M('cer-sign-unregistered', 'qce/evolve/ceremony.py', (('    if entry is None:', '    if False:'),), 'ceremonia: identidad registrada'),
    M('cer-sign-role-unchecked', 'qce/evolve/ceremony.py', (('    if entry["role"] != role:', '    if False:'),), 'ceremonia: rol registrado'),
    M('cer-sign-key-mismatch-unchecked', 'qce/evolve/ceremony.py', (('    if key.public_bytes.hex() != entry["public_key"]:', '    if False:'),), 'ceremonia: clave = registrada'),
    M('cer-sign-no-self-verify', 'qce/evolve/ceremony.py', (('    if verdict == "accept" and signer not in approvals.valid_statements(root, release_id, role):', '    if False:'),), 'ceremonia: la firma se autoverifica'),
    M('cer-fingerprint-short', 'qce/evolve/ceremony.py', (('.hexdigest()[:16]', '.hexdigest()[:8]'),), 'ceremonia: huella de 16 hex'),
    M('cer-cli-noninteractive-allowed', 'qce/cli.py', (('if not sys.stdin.isatty() and os.environ.get("QCE_ALLOW_NONINTERACTIVE_SIGN") != "1":', 'if False:'),), 'ceremonia: firmar exige terminal interactiva'),
    M('slh-seed-length-unchecked', 'qce/pqc/slhdsa.py', (('if not isinstance(seed, (bytes, bytearray)) or len(seed) != SEED_LEN:', 'if False:'),), 'SLH-DSA: longitud de la semilla'),
    M('slh-seed-ignored', 'qce/pqc/slhdsa.py', (('p, keep = _octets(b"seed", bytes(seed))', 'p, keep = _octets(b"seed", bytes(SEED_LEN))'),), 'SLH-DSA: la semilla se usa'),
    M('slh-seed-keygen-unchecked', 'qce/pqc/slhdsa.py', (('c.EVP_PKEY_CTX_set_params(ctx, params) != 1', 'False'),), 'SLH-DSA: la semilla se aplica'),
    M('e14-status-fields-unchecked', 'qce/qkd/etsi014.py', (('if not all(isinstance(d.get(k), int) and not isinstance(d.get(k), bool) and d[k] >= 0 for k in ints):', 'if False:'),), 'ETSI 014: campos del estado'),
    M('e14-status-bool-allowed', 'qce/qkd/etsi014.py', ((' and not isinstance(d.get(k), bool) and d[k] >= 0 for k in ints)', ' and d[k] >= 0 for k in ints)'),), 'ETSI 014: booleanos no son enteros'),
    M('e14-status-negative-allowed', 'qce/qkd/etsi014.py', ((' and not isinstance(d.get(k), bool) and d[k] >= 0 for k in ints)', ' and not isinstance(d.get(k), bool) for k in ints)'),), 'ETSI 014: contadores no negativos'),
    M('e14-key-count-unchecked', 'qce/qkd/etsi014.py', (('if not isinstance(keys, list) or len(keys) != count:', 'if not isinstance(keys, list):'),), 'ETSI 014: número exacto de claves'),
    M('e14-keyid-format-unchecked', 'qce/qkd/etsi014.py', (('if not isinstance(kid, str) or not KEY_ID_RE.match(kid) or not isinstance(b64, str):', 'if not isinstance(kid, str) or not isinstance(b64, str):'),), 'ETSI 014: key_ID es UUID'),
    M('e14-duplicate-keyid-allowed', 'qce/qkd/etsi014.py', (('if kid in seen or (expected_ids is not None and kid not in expected_ids):', 'if (expected_ids is not None and kid not in expected_ids):'),), 'ETSI 014: key_ID repetido'),
    M('e14-unrequested-key-allowed', 'qce/qkd/etsi014.py', (('if kid in seen or (expected_ids is not None and kid not in expected_ids):', 'if kid in seen:'),), 'ETSI 014: solo la clave pedida'),
    M('e14-base64-lenient', 'qce/qkd/etsi014.py', (('base64.b64decode(b64, validate=True)', 'base64.b64decode(b64, validate=False)'),), 'ETSI 014: base64 estricto'),
    M('e14-key-size-unchecked', 'qce/qkd/etsi014.py', (('if len(raw) * 8 != self._bits:', 'if False:'),), 'ETSI 014: tamaño de clave entregado'),
    M('e14-request-two-keys', 'qce/qkd/etsi014.py', (('{"number": 1, "size": self._bits}', '{"number": 2, "size": self._bits}'),), 'ETSI 014: se pide una clave'),
    M('e14-slave-keyid-unchecked', 'qce/qkd/etsi014.py', (('if not isinstance(want, str) or not KEY_ID_RE.match(want):', 'if False:'),), 'ETSI 014: la esclava exige key_ID'),
    M('e14-role-unchecked', 'qce/qkd/etsi014.py', (('if role not in ("master", "slave"):', 'if False:'),), 'ETSI 014: rol'),
    M('e14-sae-id-unchecked', 'qce/qkd/etsi014.py', (('if not SAE_ID_RE.match(sae or ""):', 'if False:'),), 'ETSI 014: identificador de SAE'),
    M('e14-key-size-floor-boundary', 'qce/qkd/etsi014.py', (('not KEY_SIZE_MIN <= key_size_bits <= KEY_SIZE_MAX', 'not KEY_SIZE_MIN < key_size_bits <= KEY_SIZE_MAX'),), 'ETSI 014: tamaño mínimo inclusivo'),
    M('e14-key-size-ceiling-boundary', 'qce/qkd/etsi014.py', (('not KEY_SIZE_MIN <= key_size_bits <= KEY_SIZE_MAX', 'not KEY_SIZE_MIN <= key_size_bits < KEY_SIZE_MAX'),), 'ETSI 014: tamaño máximo inclusivo'),
    M('e14-key-size-multiple-of-8-off', 'qce/qkd/etsi014.py', ((' or key_size_bits % 8:', ':'),), 'ETSI 014: múltiplo de 8'),
    M('e14-http-error-accepted', 'qce/qkd/etsi014.py', (('        if status != 200:', '        if False:'),), 'ETSI 014: solo 200 es éxito'),
    M('e14-401-category', 'qce/qkd/etsi014.py', (('401: ErrorCategory.AUTHENTICATION_FAILURE', '401: ErrorCategory.UNKNOWN_ERROR'),), 'ETSI 014: 401'),
    M('e14-400-category', 'qce/qkd/etsi014.py', (('400: ErrorCategory.PROTOCOL_MISMATCH', '400: ErrorCategory.UNKNOWN_ERROR'),), 'ETSI 014: 400'),
    M('e14-503-category', 'qce/qkd/etsi014.py', (('503: ErrorCategory.KEY_EXHAUSTION', '503: ErrorCategory.UNKNOWN_ERROR'),), 'ETSI 014: 503'),
    M('e14-remote-message-untruncated', 'qce/qkd/etsi014.py', (('.get("message", ""))[:80]', '.get("message", ""))[:8000]'),), 'ETSI 014: mensaje remoto truncado'),
    M('e14-json-dict-unchecked', 'qce/qkd/etsi014.py', (('        if not isinstance(data, dict):', '        if False:'),), 'ETSI 014: JSON objeto'),
    M('e14-simulation-flag-lost', 'qce/qkd/etsi014.py', (('            self._sim, "mutual-TLS+certificate-pin"', '            False, "mutual-TLS+certificate-pin"'),), 'ETSI 014: se declara la simulación (capacidades)'),
    M('e14-key-ref-simulation-lost', 'qce/qkd/etsi014.py', (('"session-key", KeyState.AVAILABLE, True, "", self._sim)', '"session-key", KeyState.AVAILABLE, True, "", False)'),), 'ETSI 014: se declara la simulación (clave)'),
    M('e14-fingerprint-not-sha256', 'qce/qkd/etsi014.py', (('return hashlib.sha256(self._t.peer_certificate_der()).digest()', 'return hashlib.sha1(self._t.peer_certificate_der()).digest()'),), 'ETSI 014: huella SHA-256'),
    M('e14-auth-without-init', 'qce/qkd/etsi014.py', (('        if self._registry is None:\n            raise QKDDeviceError(ErrorCategory.DEVICE_UNTRUSTED, "adaptador sin inicializar")\n        self._registry.authenticate_pinned_certificate(self)', '        self._registry.authenticate_pinned_certificate(self)'),), 'ETSI 014: autenticar exige inicializar'),
    M('e14-timeout-mapped-to-connection', 'qce/qkd/etsi014.py', (('        except socket.timeout:\n            raise QKDDeviceError(ErrorCategory.SERVICE_UNAVAILABLE, "tiempo de espera agotado con el KME") from None\n        except ssl.SSLError as exc:\n            raise QKDDeviceError(ErrorCategory.AUTHENTICATION_FAILURE, f"fallo TLS con el KME ({type(exc).__name__})") from None\n        except OSError as exc:\n            raise QKDDeviceError(ErrorCategory.CONNECTION_FAILURE, f"no hay conexión con el KME ({type(exc).__name__})") from None\n        finally:', '        except ssl.SSLError as exc:\n            raise QKDDeviceError(ErrorCategory.AUTHENTICATION_FAILURE, f"fallo TLS con el KME ({type(exc).__name__})") from None\n        except OSError as exc:\n            raise QKDDeviceError(ErrorCategory.CONNECTION_FAILURE, f"no hay conexión con el KME ({type(exc).__name__})") from None\n        finally:'),), 'ETSI 014: plazo agotado'),
    M('e14-response-limit-off', 'qce/qkd/etsi014.py', (('            if len(payload) > MAX_RESPONSE:', '            if False:'),), 'ETSI 014: tamaño máximo de respuesta'),
    M('e14-cert-required-off', 'qce/qkd/etsi014.py', (('        if not der:\n            raise QKDDeviceError(ErrorCategory.DEVICE_UNTRUSTED', '        if False:\n            raise QKDDeviceError(ErrorCategory.DEVICE_UNTRUSTED'),), 'ETSI 014: el KME presenta certificado'),
    M('dev-pinned-compare-off', 'qce/qkd/devices.py', (('if not hmac.compare_digest(bytes(got), rec.public_key):', 'if False:'),), 'registro: huella fijada'),
    M('dev-pinned-state-skipped', 'qce/qkd/devices.py', (('        if rec.trust_state in ("UNTRUSTED", "REVIEW_REQUIRED"):\n            raise QKDDeviceError(ErrorCategory.DEVICE_UNTRUSTED, f"estado {rec.trust_state}: requiere aprobación humana (approve)")\n        got =', '        got ='),), 'registro: sin re-confianza automática (certificado)'),
    M('dev-pinned-no-trust', 'qce/qkd/devices.py', (('        rec.trust_state, rec.last_successful_check = "TRUSTED", self._clock()\n        self._log("auth_ok", rec.device_id)\n\n    def approve', '        self._log("auth_ok", rec.device_id)\n\n    def approve'),), 'registro: la autenticación por certificado confía'),
    M('dev-pinned-mismatch-not-untrusted', 'qce/qkd/devices.py', (('            rec.trust_state = "UNTRUSTED"\n            self._log("identity_changed", rec.device_id)\n            raise QKDDeviceError(ErrorCategory.DEVICE_UNTRUSTED, "el certificado', '            self._log("identity_changed", rec.device_id)\n            raise QKDDeviceError(ErrorCategory.DEVICE_UNTRUSTED, "el certificado'),), 'registro: certificado distinto = no confiable'),
    M('prof-etsi-keysize-floor-off', 'qce/qkd/profiles.py', (('ksb < 128 or ksb % 8', 'ksb < 0 or ksb % 8'),), 'perfil ETSI: tamaño mínimo'),
    M('prof-etsi-keysize-boundary', 'qce/qkd/profiles.py', (('ksb < 128 or ksb % 8', 'ksb <= 128 or ksb % 8'),), 'perfil ETSI: tamaño mínimo inclusivo'),
    M('prof-etsi-keysize-multiple-off', 'qce/qkd/profiles.py', (('ksb < 128 or ksb % 8', 'ksb < 128'),), 'perfil ETSI: múltiplo de 8'),
    M('prof-etsi-keysize-type-off', 'qce/qkd/profiles.py', (('if not isinstance(ksb, int) or isinstance(ksb, bool) or ksb < 128', 'if ksb < 128'),), 'perfil ETSI: tipo del tamaño'),
    M('prof-hops-from-spec-off', 'qce/qkd/profiles.py', (('else (spec or {}).get("trusted_hops")', 'else 0'),), 'perfil ETSI: saltos desde la ficha'),
    M('prof-hops-missing-reported-invalid', 'qce/qkd/profiles.py', (('if hops is None and "trusted_hops" not in profile.witnesses:\n        pass', 'if False:\n        pass'),), 'perfil ETSI: ficha ausente es política'),
    M('qkdb-per-key-flag-off', 'qce/qkd/broker.py', (('profiles.profile_for(self._caps[link_id][0]).per_key_witnesses and evidence', 'evidence'),), 'broker: testigos por clave solo si el perfil los da'),
    M("slh-verify-accepts-zero", "qce/pqc/slhdsa.py", (("if c.EVP_DigestVerify(mctx, s, len(sig), msg, len(message)) != 1:", "if c.EVP_DigestVerify(mctx, s, len(sig), msg, len(message)) < 0:"),), "SLH-DSA: solo 1 es válida"),
    M("slh-verify-length-off", "qce/pqc/slhdsa.py", (("    if len(pk) != PK_LEN or len(sig) != SIG_LEN:\n        raise MalformedMessage", "    if False:\n        raise MalformedMessage"),), "SLH-DSA: longitudes en la verificación"),
    M("slh-context-ignored-sign", "qce/pqc/slhdsa.py", (("    if context:\n        p, b = _octets(b\"context-string\"", "    if False:\n        p, b = _octets(b\"context-string\""),), "SLH-DSA: contexto en la firma"),
    M("slh-context-limit-off", "qce/pqc/slhdsa.py", (("len(context) > CONTEXT_MAX:", "False:"),), "SLH-DSA: límite de contexto"),
    M("slh-context-limit-boundary", "qce/pqc/slhdsa.py", (("len(context) > CONTEXT_MAX:", "len(context) >= CONTEXT_MAX:"),), "SLH-DSA: límite de contexto inclusivo"),
    M("slh-deterministic-ignored", "qce/pqc/slhdsa.py", (("    if deterministic:\n        det = ctypes.c_int(1)", "    if False:\n        det = ctypes.c_int(1)"),), "SLH-DSA: modo determinista"),
    M("slh-sign-length-unchecked", "qce/pqc/slhdsa.py", (("c.EVP_DigestSign(mctx, sig, ctypes.byref(n), msg, len(message)) != 1 or n.value != expected", "c.EVP_DigestSign(mctx, sig, ctypes.byref(n), msg, len(message)) != 1"),), "SLH-DSA: longitud de la firma producida"),
    M("slh-from-bytes-length-off", "qce/pqc/slhdsa.py", (("        if len(sk) != SK_LEN:\n            raise MalformedMessage", "        if False:\n            raise MalformedMessage"),), "SLH-DSA: longitud de la clave privada"),
    M("slh-public-part-wrong", "qce/pqc/slhdsa.py", (("return cls(sk, bytes(sk[PK_LEN:]))", "return cls(sk, bytes(sk[:PK_LEN]))"),), "SLH-DSA: parte pública de la privada"),
    M("slh-export-length-unchecked", "qce/pqc/slhdsa.py", (("or n.value != size:", ":"),), "SLH-DSA: longitud al exportar"),
    M("cust-autorot-never", "qce/transport/custody.py", (("            if remaining > renew_before_s:\n                return None", "            if True:\n                return None"),), "custodia: rotación automática"),
    M("cust-autorot-always", "qce/transport/custody.py", (("            if remaining > renew_before_s:\n                return None", "            if False:\n                return None"),), "custodia: no rota sin necesidad"),
    M("cust-autorot-boundary", "qce/transport/custody.py", (("            if remaining > renew_before_s:\n                return None", "            if remaining >= renew_before_s:\n                return None"),), "custodia: rotación en el límite"),
    M("cust-autorot-server-not-updated", "qce/transport/custody.py", (("        if server is not None:\n            server.set_context(self.server_context(new))", "        if False:\n            server.set_context(self.server_context(new))"),), "custodia: el servidor recibe el contexto nuevo"),
    M("cust-autorot-expired-not-recovered", "qce/transport/custody.py", (("        except KeyStateError:\n            new = self.provision_with_lab_ca", "        except ZeroDivisionError:\n            new = self.provision_with_lab_ca"),), "custodia: recuperación tras caducar"),
    M("cust-revoked-list-wrong-state", "qce/transport/custody.py", (("self._store.info(k).state is State.REVOKED and (self._certs", "self._store.info(k).state is State.RETIRED and (self._certs"),), "custodia: certificados revocados para la CRL"),
    M("tls-crl-check-off", "qce/transport/tls13.py", (("        ctx.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF", "        pass"),), "transporte: comprobación de CRL"),
    M("tls-crl-not-loaded", "qce/transport/tls13.py", (("    if crl_file is not None:\n        ctx.load_verify_locations(str(crl_file))\n", "    if crl_file is not None:\n"),), "transporte: CRL cargada (falla cerrado)"),
    M("psk-error-queue-not-cleared", "qce/transport/tls13_psk.py", (("            self._c.ERR_clear_error()   # la cola de errores es POR HILO", "            pass   # la cola de errores es POR HILO"),), "PSK: cola de errores por hilo"),
    M("psk-info-label-off", "qce/transport/tls13_psk.py", (('info=PSK_INFO + _lp(bytes(identity))', 'info=_lp(bytes(identity))'),), "PSK: etiqueta de dominio"),
    M("psk-identity-context-off", "qce/transport/tls13_psk.py", (('info=PSK_INFO + _lp(bytes(identity))', 'info=PSK_INFO'),), "PSK: el identificador entra en la derivación"),
    M("psk-key-min-boundary", "qce/transport/tls13_psk.py", (('not QKD_KEY_MIN <= len(qkd_key)', 'not QKD_KEY_MIN < len(qkd_key)'),), "PSK: tamaño mínimo de clave inclusivo"),
    M("psk-key-max-boundary", "qce/transport/tls13_psk.py", (('<= len(qkd_key) <= QKD_KEY_MAX', '<= len(qkd_key) < QKD_KEY_MAX'),), "PSK: tamaño máximo de clave inclusivo"),
    M("psk-key-range-off", "qce/transport/tls13_psk.py", (('if not isinstance(qkd_key, (bytes, bytearray)) or not QKD_KEY_MIN <= len(qkd_key) <= QKD_KEY_MAX:', 'if False:'),), "PSK: rango de la clave QKD"),
    M("psk-ident-min-boundary", "qce/transport/tls13_psk.py", (('not 1 <= len(identity) <= IDENT_MAX:\n        raise MalformedMessage', 'not 1 < len(identity) <= IDENT_MAX:\n        raise MalformedMessage'),), "PSK: id mínimo inclusivo"),
    M("psk-ident-max-boundary", "qce/transport/tls13_psk.py", (('not 1 <= len(identity) <= IDENT_MAX:\n        raise MalformedMessage', 'not 1 <= len(identity) < IDENT_MAX:\n        raise MalformedMessage'),), "PSK: id máximo inclusivo"),
    M("psk-length-short", "qce/transport/tls13_psk.py", (('PSK_LEN = 32', 'PSK_LEN = 16'),), "PSK: 32 bytes"),
    M("psk-attest-skipped", "qce/transport/tls13_psk.py", (('        _attest(conn, suite, group)\n    except BaseException:\n        conn.close()\n        raise\n    return conn', '    except BaseException:\n        conn.close()\n        raise\n    return conn'),), "PSK: atestación del cliente"),
    M("psk-attest-server-skipped", "qce/transport/tls13_psk.py", (('        _attest(conn, suite, group)\n        if state["id"] is None:', '        if state["id"] is None:'),), "PSK: atestación del servidor"),
    M("psk-attest-group-off", "qce/transport/tls13_psk.py", (('    if conn.group != REPORTED_GROUP_NAME[group]:', '    if False:'),), "PSK: grupo híbrido atestiguado"),
    M("psk-attest-version-off", "qce/transport/tls13_psk.py", (('    if conn.version != "TLSv1.3":', '    if False:'),), "PSK: TLS 1.3 atestiguado"),
    M("psk-attest-suite-off", "qce/transport/tls13_psk.py", (('    if conn.cipher != suite:', '    if False:'),), "PSK: suite atestiguada"),
    M("psk-attest-psk-used-off", "qce/transport/tls13_psk.py", (('    if require_psk and not conn.psk_used:', '    if False:'),), "PSK: uso de la PSK atestiguado"),
    M("psk-suite-allowlist-off", "qce/transport/tls13_psk.py", (('    if suite not in SUITES:', '    if False:'),), "PSK: suites permitidas"),
    M("psk-server-commit-skipped", "qce/transport/tls13_psk.py", (('        raise\n    source.commit(state["id"])\n    return conn', '        raise\n    return conn'),), "PSK: consumo único tras completar"),
    M("psk-server-release-skipped", "qce/transport/tls13_psk.py", (('        if state["id"] is not None:\n            source.release(state["id"])\n        conn.close()', '        conn.close()'),), "PSK: la clave vuelve si el apretón falla"),
    M("psk-server-short-key-kept", "qce/transport/tls13_psk.py", (('                    source.commit(ident)   # material fuera de rango: inservible, se descarta\n', '                    pass\n'),), "PSK: clave inservible se descarta"),
    M("psk-server-no-reserve", "qce/transport/tls13_psk.py", (('                key = source.reserve(ident)\n                if key is None:', '                key = source._keys.get(ident) if hasattr(source, "_keys") else source.reserve(ident)\n                if key is None:'),), "PSK: reserva exclusiva"),
    M("psk-timeout-ignored", "qce/transport/tls13_psk.py", (('                if left <= 0:\n                    raise TimeoutError', '                if False:\n                    raise TimeoutError'),), "PSK: plazo del apretón"),
    M("psk-closed-peer-unreported", "qce/transport/tls13_psk.py", (('            if e == 6:  # SSL_ERROR_ZERO_RETURN\n                raise MalformedMessage("conexión cerrada por el par")\n', ''),), "PSK: cierre del par"),
    M("psk-send-limit-off", "qce/transport/tls13_psk.py", (('        if len(data) > MAX_FRAME:\n            raise MalformedMessage("mensaje demasiado grande")', '        if False:\n            raise MalformedMessage("mensaje demasiado grande")'),), "PSK: tamaño máximo de mensaje (envío)"),
    M("psk-recv-limit-off", "qce/transport/tls13_psk.py", (('        if n > max_size:\n            raise MalformedMessage("mensaje mayor', '        if False:\n            raise MalformedMessage("mensaje mayor'),), "PSK: tamaño máximo de mensaje (recepción)"),
    M("psk-lib-version-floor-off", "qce/transport/tls13_psk.py", (('if crypto.OpenSSL_version_num() < OPENSSL_MIN:', 'if False:'),), "PSK: OpenSSL ≥ 3.5"),
    M("qil-server-key-range-off", "qce/transport/qkd_layer.py", (("            _check_key(qkd_key)\n        except PolicyViolation:", "            pass\n        except PolicyViolation:"),), "QIL1: el servidor valida la clave que entrega la fuente"),
    M("qil-short-key-kept", "qce/transport/qkd_layer.py", (("source.commit(key_id)  # material fuera de rango: inservible, se descarta", "pass"),), "QIL1: clave inservible se descarta"),
    M("qil-unknown-key-accepted", "qce/transport/qkd_layer.py", (("        if qkd_key is None:\n            raise AuthenticationFailure(\"clave QKD desconocida, reservada", "        if False:\n            raise AuthenticationFailure(\"clave QKD desconocida, reservada"),), "QIL1: clave desconocida, reservada o consumida"),
    M("qil-same-key-both-directions", "qce/transport/qkd_layer.py", (("return Layer(sock, _expand(qkd_key, th, INFO_C2S), _expand(qkd_key, th, INFO_S2C), th)", "return Layer(sock, _expand(qkd_key, th, INFO_C2S), _expand(qkd_key, th, INFO_C2S), th)"), ("layer = Layer(sock, _expand(qkd_key, th, INFO_S2C), _expand(qkd_key, th, INFO_C2S), th)", "layer = Layer(sock, _expand(qkd_key, th, INFO_C2S), _expand(qkd_key, th, INFO_C2S), th)")), "QIL1: una clave por dirección"),
    M("qil-commit-skipped", "qce/transport/qkd_layer.py", (("        source.commit(key_id)\n        layer = Layer", "        layer = Layer"),), "QIL1: consumo único tras completar"),
    M("qil-release-skipped", "qce/transport/qkd_layer.py", (("            source.release(key_id)\n            raise", "            raise"),), "QIL1: la clave vuelve si el apretón falla (sin gasto de claves)"),
    M("qil-handshake-timeout-off", "qce/transport/qkd_layer.py", (("    sock.settimeout(HANDSHAKE_TIMEOUT)", "    pass"),), "QIL1: plazo del apretón"),
    M("qil-timeout-not-restored", "qce/transport/qkd_layer.py", (("    finally:\n        sock.settimeout(previous)", "    finally:\n        pass"),), "QIL1: el plazo se restaura"),
    M("qil-store-reserve-ignores-reservation", "qce/qkd/sources.py", (("if kid in self._reserved or kid not in self._keys:", "if kid not in self._keys:"),), "QIL1: reserva exclusiva"),
    M("qil-store-commit-keeps-key", "qce/qkd/sources.py", (("            self._keys.pop(bytes(key_id), None)\n            self._reserved.discard(bytes(key_id))", "            self._reserved.discard(bytes(key_id))"),), "QIL1: consumo único (almacén)"),
    M("qil-broker-source-nonascii-uncaught", "qce/qkd/sources.py", (("PolicyViolation, UnicodeDecodeError):\n            return None", "PolicyViolation):\n            return None"),), "QIL1: broker, id no ASCII"),
    M("qil-broker-source-policy-uncaught", "qce/qkd/sources.py", (("QKDAnomaly, PolicyViolation, UnicodeDecodeError)", "QKDAnomaly, UnicodeDecodeError)"),), "QIL1: broker, consumidor no autorizado"),
    M("qil-broker-source-anomaly-uncaught", "qce/qkd/sources.py", (("except (QKDDeviceError, QKDAnomaly, PolicyViolation", "except (QKDDeviceError, PolicyViolation"),), "QIL1: broker, enlace en cuarentena"),
    M("qil-broker-source-device-error-uncaught", "qce/qkd/sources.py", (("except (QKDDeviceError, QKDAnomaly,", "except (QKDAnomaly,"),), "QIL1: broker, error de dispositivo"),
    M("qil-broker-source-release-noop", "qce/qkd/sources.py", (("        self._b.release(key_id.decode(\"ascii\"), self._consumer)", "        pass"),), "QIL1: el broker recupera la clave si el apretón falla"),
    M("qkdb-peek-state-off", "qce/qkd/broker.py", (("if ref.state is not KeyState.RESERVED or ref.reserved_by != consumer:\n            raise QKDDeviceError(ErrorCategory.KEY_EXPIRED, f\"clave no reservada", "if False:\n            raise QKDDeviceError(ErrorCategory.KEY_EXPIRED, f\"clave no reservada"),), "broker: lectura solo con reserva propia"),
    M("qkdb-peek-owner-off", "qce/qkd/broker.py", (("or ref.reserved_by != consumer:\n            raise QKDDeviceError(ErrorCategory.KEY_EXPIRED, f\"clave no reservada", ":\n            raise QKDDeviceError(ErrorCategory.KEY_EXPIRED, f\"clave no reservada"),), "broker: lectura solo del dueño de la reserva"),
    M("qkdb-release-owner-off", "qce/qkd/broker.py", (("if ref is not None and ref.state is KeyState.RESERVED and ref.reserved_by == consumer:", "if ref is not None and ref.state is KeyState.RESERVED:"),), "broker: solo el dueño libera"),
    M("qkdb-release-state-off", "qce/qkd/broker.py", (("if ref is not None and ref.state is KeyState.RESERVED and ref.reserved_by == consumer:", "if ref is not None and ref.reserved_by == consumer:"),), "broker: una clave consumida no resucita"),
    M("qkdb-release-noop", "qce/qkd/broker.py", (("            ref.state, ref.reserved_by = KeyState.AVAILABLE, \"\"\n", "            pass\n"),), "broker: liberar devuelve la clave"),

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
    M("qil-client-key-range-off", "qce/transport/qkd_layer.py", (("    _check_key_id(key_id)\n    _check_key(qkd_key)\n    bind", "    _check_key_id(key_id)\n    bind"),), "QIL1: el cliente valida su clave"),
    M("qil-key-id-min-boundary", "qce/transport/qkd_layer.py", (("not 1 <= len(key_id) <= KEY_ID_MAX", "not 1 < len(key_id) <= KEY_ID_MAX"),), "QIL1: id mínimo inclusivo"),
    M("qil-key-id-max-boundary", "qce/transport/qkd_layer.py", (("not 1 <= len(key_id) <= KEY_ID_MAX", "not 1 <= len(key_id) < KEY_ID_MAX"),), "QIL1: id máximo inclusivo"),
    M("qil-hello-version-off", "qce/transport/qkd_layer.py", (("or data[:4] != VERSION:", "or False:"),), "QIL1: versión exacta del HELLO"),
    M("qil-hello-length-loose", "qce/transport/qkd_layer.py", (("len(data) != 5 + n + NONCE_LEN", "len(data) < 5 + n + NONCE_LEN"),), "QIL1: longitud exacta del HELLO"),
    M("qil-hello-id-bounds-off", "qce/transport/qkd_layer.py", (("if not 1 <= n <= KEY_ID_MAX or len(data)", "if len(data)"),), "QIL1: límites del id en el HELLO"),
    M("qil-accept-length-loose", "qce/transport/qkd_layer.py", (("if len(accept) != NONCE_LEN + TAG_LEN:", "if len(accept) < NONCE_LEN + TAG_LEN:"),), "QIL1: longitud exacta del ACCEPT"),
    M("qil-aad-off", "qce/transport/qkd_layer.py", (("        return REC_AAD_LABEL + self._th", "        return b\"\""),), "QIL1: AAD liga el registro a la sesión"),
    M("qil-send-counter-frozen", "qce/transport/qkd_layer.py", (("        self._n_out += 1", "        pass"),), "QIL1: contador de envío"),
    M("qil-recv-counter-frozen", "qce/transport/qkd_layer.py", (("        self._n_in += 1", "        pass"),), "QIL1: contador de recepción"),
    M("qil-write-limit-off", "qce/transport/qkd_layer.py", (("        if self._n_out >= MAX_RECORDS:", "        if False:"),), "QIL1: tope de registros (envío)"),
    M("qil-write-limit-boundary", "qce/transport/qkd_layer.py", (("        if self._n_out >= MAX_RECORDS:", "        if self._n_out > MAX_RECORDS:"),), "QIL1: tope de registros (envío) inclusivo"),
    M("qil-read-limit-off", "qce/transport/qkd_layer.py", (("        if self._n_in >= MAX_RECORDS:", "        if False:"),), "QIL1: tope de registros (recepción)"),
    M("qil-plaintext-limit-off", "qce/transport/qkd_layer.py", (("        if len(data) > MAX_PLAINTEXT:", "        if False:"),), "QIL1: tamaño máximo de registro"),
    M("qil-plaintext-limit-boundary", "qce/transport/qkd_layer.py", (("        if len(data) > MAX_PLAINTEXT:", "        if len(data) >= MAX_PLAINTEXT:"),), "QIL1: tamaño máximo de registro inclusivo"),
    M("qil-client-recv-key-wrong", "qce/transport/qkd_layer.py", (("return Layer(sock, _expand(qkd_key, th, INFO_C2S), _expand(qkd_key, th, INFO_S2C), th)", "return Layer(sock, _expand(qkd_key, th, INFO_C2S), _expand(qkd_key, th, INFO_C2S), th)"),), "QIL1: clave por dirección (cliente)"),
]


SANDBOX_FILES = ("pytest.ini", "THREAT_MODEL.md", "LIMITATIONS.md", "gates.json", "requirements.lock", "requirements.hashes.txt", "sbom.cdx.json")


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
