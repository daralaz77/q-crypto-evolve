import json

import pytest

from qce.core.chainlog import ChainLog, sanitize
from qce.core.errors import (AuthenticationFailure, IntegrityError, KeyStateError, PolicyViolation,
                             QKDAnomaly)
from qce.core.policy import Policy
from qce.key_management import vault
from qce.key_management.keystore import KeyStore, Purpose, State
from qce.qkd.adapter import QKDIngestor, SimulatedQKDDevice


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


@pytest.fixture
def ks(tmp_path):
    clock = Clock()
    return KeyStore(ChainLog(tmp_path / "audit.jsonl", clock), clock), clock


def active(store, purpose=Purpose.ENCRYPT, ttl=100):
    kid = store.create(purpose, ttl)
    store.activate(kid)
    return kid


def test_envelope_roundtrip_and_aad_binding(ks):
    store, _ = ks
    kid = active(store)
    blob = store.protect(kid, b"secreto", b"ctx")
    assert store.unprotect(blob, b"ctx") == b"secreto"
    with pytest.raises(AuthenticationFailure):
        store.unprotect(blob, b"otro")
    assert store.protect(kid, b"secreto", b"ctx") != blob  # sal fresca → subclave distinta


def test_purpose_separation(ks):
    store, _ = ks
    kid = active(store, Purpose.SIGN)
    with pytest.raises(KeyStateError):
        store.protect(kid, b"x")
    assert any(json.loads(e["body"])["event"] == "misuse" for e in store._audit.entries())


def test_lifecycle_illegal_transitions(ks):
    store, _ = ks
    kid = store.create(Purpose.ENCRYPT, 100)
    with pytest.raises(KeyStateError):
        store.revoke(kid, "x")  # GENERATED → REVOKED no existe
    with pytest.raises(KeyStateError):
        store.protect(kid, b"x")  # aún no activa
    store.activate(kid)
    with pytest.raises(KeyStateError):
        store.activate(kid)
    store.destroy_ok = None
    store.revoke(kid, "compromiso")
    store.destroy(kid)
    with pytest.raises(KeyStateError):
        store.activate(kid)


def test_rotation_keeps_old_data_readable_but_not_writable(ks):
    store, _ = ks
    old = active(store)
    blob = store.protect(old, b"viejo")
    new = store.rotate(old, 100)
    assert store.info(old).state is State.RETIRED and store.info(new).generation == 2
    assert store.unprotect(blob) == b"viejo"
    with pytest.raises(KeyStateError):
        store.protect(old, b"nuevo")
    store.protect(new, b"nuevo")


def test_revocation_blocks_everything_and_zeroizes(ks):
    store, _ = ks
    kid = active(store)
    blob = store.protect(kid, b"x")
    store.revoke(kid, "filtración")
    with pytest.raises(KeyStateError):
        store.unprotect(blob)
    assert store.info(kid).secret is None


def test_expiry_blocks_new_protection_only(ks):
    store, clock = ks
    kid = active(store, ttl=10)
    blob = store.protect(kid, b"x")
    clock.t += 11
    with pytest.raises(KeyStateError):
        store.protect(kid, b"y")
    assert store.unprotect(blob) == b"x"


def test_audit_chain_detects_tamper_and_truncation(ks, tmp_path):
    store, _ = ks
    kid = active(store)
    store.rotate(kid, 100)
    log = store._audit
    head = log.head()
    assert log.verify(head) >= 4
    lines = log.path.read_text().splitlines()
    log.path.write_text("\n".join(lines[:-1]) + "\n")  # truncado
    with pytest.raises(IntegrityError):
        log.verify(head)
    e = json.loads(lines[1])
    e["body"] = e["body"].replace("activate", "ACTIVATE")
    lines[1] = json.dumps(e)
    log.path.write_text("\n".join(lines) + "\n")
    with pytest.raises(IntegrityError):
        log.verify()


def test_sanitize_never_logs_secrets():
    s = sanitize({"k": b"\x01" * 32, "t": "password=hunter2 y " + "ab" * 40, "pem": "-----BEGIN PRIVATE KEY-----\nAAA\n-----END PRIVATE KEY-----"})
    dumped = json.dumps(s)
    assert "hunter2" not in dumped and "abab" not in dumped and "AAA" not in dumped


def test_vault_roundtrip_tamper_wrong_pass_and_rollback(ks, tmp_path):
    store, _ = ks
    kid = active(store)
    blob = store.protect(kid, b"persistente")
    p = tmp_path / "v.bin"
    vault.save(store, p, "frase-larga", n=2**14)
    assert oct(p.stat().st_mode & 0o777) == "0o600"
    again = vault.load(p, "frase-larga")
    assert again.unprotect(blob) == b"persistente"
    with pytest.raises(AuthenticationFailure):
        vault.load(p, "otra")
    raw = bytearray(p.read_bytes())
    raw[-1] ^= 1
    q = tmp_path / "v2.bin"
    q.write_bytes(bytes(raw))
    with pytest.raises(AuthenticationFailure):
        vault.load(q, "frase-larga")
    old_epoch = store.epoch
    store.revoke(kid, "x")
    vault.save(store, tmp_path / "v3.bin", "frase-larga", n=2**14)
    with pytest.raises(IntegrityError):  # restaurar la copia previa a la revocación
        vault.load(p, "frase-larga", min_epoch=store.epoch)
    assert old_epoch < store.epoch


def test_vault_has_no_plaintext_secret(ks, tmp_path):
    store, _ = ks
    kid = active(store)
    secret_hex = bytes(store.info(kid).secret).hex().encode()
    vault.save(store, tmp_path / "v.bin", "frase-larga", n=2**14)
    assert secret_hex not in (tmp_path / "v.bin").read_bytes()


# ---- QKD ---------------------------------------------------------------------------
AUTH = b"a" * 32


def lab_policy():
    return Policy(allow_simulated_qkd=True)


def test_simulated_qkd_rejected_in_production_policy():
    k = SimulatedQKDDevice(AUTH, seed=1).fetch_key("peer")
    with pytest.raises(PolicyViolation):
        QKDIngestor(Policy(), AUTH).ingest(k)


def test_qkd_accepts_clean_channel_and_consumes_once():
    ing = QKDIngestor(lab_policy(), AUTH)
    k = SimulatedQKDDevice(AUTH, seed=1).fetch_key("peer")
    ing.ingest(k)
    assert ing.take(k.key_id) == k.key and ing.take(k.key_id) is None
    with pytest.raises(PolicyViolation):
        ing.ingest(k)  # reutilización del mismo key_id


def test_qkd_detects_eavesdropper_and_bad_auth():
    ing = QKDIngestor(lab_policy(), AUTH)
    with pytest.raises(QKDAnomaly):
        ing.ingest(SimulatedQKDDevice(AUTH, eavesdropper=True, seed=2).fetch_key("peer"))
    assert ing.monitor.alerts and ing.monitor.alerts[0].startswith("ABORT")
    with pytest.raises(AuthenticationFailure):
        ing.ingest(SimulatedQKDDevice(b"b" * 32, seed=3).fetch_key("peer"))


def test_qkd_qber_boundary():
    from dataclasses import replace
    ing = QKDIngestor(lab_policy(), AUTH)
    from qce.qkd.adapter import sign_key
    base = SimulatedQKDDevice(AUTH, seed=4).fetch_key("p")

    def with_qber(q, kid):
        return replace(base, key_id=kid, qber=q, tag=sign_key(AUTH, kid, base.key, q))
    ing.ingest(with_qber(0.109, b"1" * 16))
    with pytest.raises(QKDAnomaly):
        ing.ingest(with_qber(0.11, b"2" * 16))  # el umbral es inclusivo
    with pytest.raises(QKDAnomaly):
        ing.ingest(with_qber(float("nan"), b"3" * 16))
