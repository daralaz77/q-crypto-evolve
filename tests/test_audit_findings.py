"""Regresiones de la auditoría adversarial independiente (agente a32c6ce…, 2026-10-17). Una por hallazgo confirmado."""
import json
import shutil
import sys
import threading
from pathlib import Path

import pytest

from qce.core.chainlog import ChainLog, sanitize
from qce.core.errors import (AuthenticationFailure, IntegrityError, KeyStateError, PolicyViolation, QCEError)
from qce.evolve import gates, mutation
from qce.security import approvals
from qce.evolve.workflow import Task, Workflow
from qce.key_management import vault
from qce.key_management.keystore import KeyStore, Purpose, State
from qce.learning.ledger import Incident, Ledger
from qce.pqc.hybrid import HybridKemPrivateKey, HybridSigPrivateKey, hybrid_encapsulate
from qce.protocols.session import ClientHandshake, ServerHandshake, T_CF
from qce.core.encoding import pack
from qce.qkd.contract import ErrorCategory, QKDDeviceError
from qce.recovery import release as rel
from qce.security import scanners

ROOT = Path(__file__).resolve().parent.parent


def mini_project(tmp: Path) -> Path:
    (tmp / "qce").mkdir()
    (tmp / "qce" / "m.py").write_text("def f(x):\n    if x in (1, 2):\n        return True\n    return False\n")
    (tmp / "tests").mkdir()
    (tmp / "tests" / "test_m.py").write_text("from qce.m import f\n\n\ndef test_f():\n    assert f(1) and not f(9)\n")
    (tmp / "pytest.ini").write_text("[pytest]\ntestpaths = tests\n")
    for f in ("requirements.lock", "requirements.hashes.txt", "sbom.cdx.json"):
        shutil.copy2(ROOT / f, tmp / f)
    (tmp / "gates.json").write_text(json.dumps({"min_tests": 1, "min_mutation_score": 1.0, "max_open_high": 0, "min_mutants": 0, "max_declared_equivalent": 100}))
    return tmp


# ---- H1: el arnés de mutación no puede dar 1.0 con un sandbox roto --------------------------------------
def test_mutation_harness_canary_survives_real_mutant_dies_and_broken_baseline_is_refused(tmp_path, monkeypatch):
    root = mini_project(tmp_path)
    monkeypatch.setattr(mutation, "MUTANTS", [
        mutation.Mutant("real", "qce/m.py", (("return True", "return False"),), "g"),
        mutation.Mutant("CANARY-noop", "qce/m.py", (("if x in (1, 2):", "if (x in (1, 2)):"),), "g", "canary"),
    ])
    r = mutation.run_mutants(root)
    by = {d["name"]: d["killed"] for d in r["detail"]}
    assert by["real"] is True and by["CANARY-noop"] is False and r["score"] == 1.0
    (root / "tests" / "test_m.py").write_text("import archivo_inexistente\n")  # sandbox/base rotos
    with pytest.raises(RuntimeError, match="línea base"):
        mutation.run_mutants(root)


def test_mutation_collection_error_is_not_counted_as_detection(tmp_path, monkeypatch):
    root = mini_project(tmp_path)
    monkeypatch.setattr(mutation, "MUTANTS", [mutation.Mutant("syntax", "qce/m.py", (("def f(x):", "def f(x:"),), "g")])
    with pytest.raises(RuntimeError, match="no es un fallo de prueba"):
        mutation.run_mutants(root)  # rc=2 (error de colección) ya no cuenta como "killed"


# ---- H2: el trinquete no se anula evaluando dos veces ------------------------------------------------------
def test_ratchet_survives_repeated_evaluation_with_weakened_thresholds(tmp_path):
    root = mini_project(tmp_path)
    kw = dict(version="t", run_mutation=False, run_dep_audit=False)
    gates.evaluate(root, **kw)  # registra min_tests=1, mutation=1.0
    (root / "gates.json").write_text(json.dumps({"min_tests": 1, "min_mutation_score": 1.0, "max_open_high": 0, "min_mutants": 0, "max_declared_equivalent": 100}))
    ChainLog(root / "learning" / "version_history.jsonl").append({"event": "x", "thresholds": {"min_tests": 50, "min_mutation_score": 1.0, "max_open_high": 0, "min_mutants": 0, "max_declared_equivalent": 100}})
    for _ in range(3):  # antes: la 2.ª evaluación daba "pass"
        rep = gates.evaluate(root, **kw)
        g1 = next(g for g in rep["gates"] if g["gate"].startswith("G1"))
        assert g1["status"] == "blocked" and "debilitado" in g1["detail"]
    assert gates.strictest_baseline(ChainLog(root / "learning" / "version_history.jsonl"))["min_tests"] == 50
    last = json.loads(ChainLog(root / "learning" / "version_history.jsonl").entries()[-1]["body"])
    assert last["thresholds"]["min_tests"] == 50  # nunca se registra el valor débil (1) como si fuera el vigente


def test_root_conftest_blocks_gate_g1(tmp_path):
    root = mini_project(tmp_path)
    (root / "conftest.py").write_text("# convierte fallos en 'passed'\n")
    rep = gates.evaluate(root, version="t", run_mutation=False, run_dep_audit=False)
    g1 = next(g for g in rep["gates"] if g["gate"].startswith("G1"))
    assert g1["status"] == "blocked" and "conftest.py" in g1["detail"]


def test_release_id_covers_root_conftest_and_test_data(tmp_path):
    root = mini_project(tmp_path)
    a = rel.build_manifest(root, "1", {}, [], {})["release_id"]
    (root / "conftest.py").write_text("x = 1\n")
    b = rel.build_manifest(root, "1", {}, [], {})["release_id"]
    (root / "tests" / "datos.json").write_text("{}")
    c = rel.build_manifest(root, "1", {}, [], {})["release_id"]
    assert len({a, b, c}) == 3


# ---- H3: máquina de estados sin atajos ------------------------------------------------------------------------
def mk(tid="T1", risk=3):
    return Task(tid, "obj", "m", "0", "TM", ["criterio"], "IMPLEMENTER", ["pytest"], [], risk, [])


def test_review_required_is_not_a_shortcut_to_verification(tmp_path):
    wf = Workflow(tmp_path / "t.jsonl")
    wf.create(mk())
    wf.transition("T1", "REVIEW_REQUIRED", "IMPLEMENTER", "x")
    for target, role in (("INDEPENDENT_REVIEW", "VERIFIER"), ("VERIFIED", "VERIFIER"), ("RELEASE_REVIEW", "RELEASE-GUARDIAN"),
                         ("RELEASE_APPROVED", "HUMAN")):  # con el rol CORRECTO para cada estado: lo que falla es el camino
        with pytest.raises(QCEError, match="transición no permitida"):
            wf.transition("T1", target, role, "x2", ["run:1", "approval:x"])


def test_findings_cannot_be_erased_by_passing_an_empty_list(tmp_path):
    wf = Workflow(tmp_path / "t.jsonl")
    wf.create(mk(risk=2))
    for to, role, who in (("ANALYZED", "ARCHITECT", "a"), ("APPROVED_FOR_IMPLEMENTATION", "ARCHITECT", "a"),
                          ("IMPLEMENTED", "IMPLEMENTER", "impl"), ("TESTING", "VERIFIER", "v")):
        wf.transition("T1", to, role, who)
    wf.transition("T1", "INDEPENDENT_REVIEW", "VERIFIER", "v", ["run:1"], blocking_findings=["CRIT-1"])
    with pytest.raises(QCEError):
        wf.transition("T1", "VERIFIED", "VERIFIER", "v", ["run:2"], blocking_findings=[])  # antes: borraba CRIT-1
    with pytest.raises(QCEError):
        wf.resolve_finding("T1", "CRIT-1", "VERIFIER", "impl", ["run:3"])  # el implementador no cierra lo suyo
    with pytest.raises(QCEError):
        wf.resolve_finding("T1", "CRIT-1", "VERIFIER", "v", [])  # sin evidencia
    wf.resolve_finding("T1", "CRIT-1", "VERIFIER", "v", ["run:3"])
    wf.transition("T1", "VERIFIED", "VERIFIER", "v", ["run:4"])


def test_edited_task_log_is_rejected_when_state_is_read(tmp_path):
    p = tmp_path / "t.jsonl"
    wf = Workflow(p)
    wf.create(mk())
    p.write_text(p.read_text().replace("CREATED", "ABANDONED"))
    with pytest.raises(IntegrityError):
        wf.state("T1")


# ---- H4: reversión y snapshot estable ------------------------------------------------------------------------------
def snap(root, key, name="humano"):
    m = rel.build_manifest(root, "1", {}, [], {})
    d = rel.save_release(root, m)
    approvals.register(root, "approver", name, key.public_bytes) if not (root / "trust").exists() else None
    approvals.sign_statement(root, key, "approver", name, m["release_id"], "accept")
    return m, d


def test_manifest_with_traversal_paths_is_refused_and_nothing_is_written(tmp_path):
    root = mini_project(tmp_path / "p") if (tmp_path / "p").mkdir() is None else None
    key = HybridSigPrivateKey.generate()
    m, d = snap(root, key)
    rel.mark_stable(root, m["release_id"], "humano")
    import hashlib
    evil = d / "src" / "evil"
    evil.parent.mkdir(exist_ok=True)
    for bad in ("../outside_target", "./learning/incidents.jsonl", "/etc/passwd_x", "qce/../../x"):
        mm = json.loads((d / "manifest.json").read_text())
        mm["files"][bad] = hashlib.sha256(b"PWNED").hexdigest()
        (d / "manifest.json").write_text(json.dumps(mm))
        with pytest.raises(IntegrityError):
            rel.rollback(root)
        mm["files"].pop(bad)
        (d / "manifest.json").write_text(json.dumps(mm))
    assert not (tmp_path / "outside_target").exists()


def test_rollback_never_restores_gates_json_or_learning_and_stable_needs_a_valid_signature(tmp_path):
    (tmp_path / "p").mkdir()
    root = mini_project(tmp_path / "p")
    (root / "learning").mkdir()
    (root / "learning" / "incidents.jsonl").write_text("evidencia\n")
    key = HybridSigPrivateKey.generate()
    m, d = snap(root, key)
    rel.mark_stable(root, m["release_id"], "humano")
    (root / "gates.json").write_text(json.dumps({"min_tests": 999, "min_mutation_score": 1.0, "max_open_high": 0, "min_mutants": 0, "max_declared_equivalent": 100}))
    (root / "learning" / "incidents.jsonl").write_text("evidencia NUEVA\n")
    (root / "qce" / "m.py").write_text("roto\n")
    restored = rel.rollback(root)
    assert "gates.json" not in restored and not any(r.startswith("learning/") for r in restored)
    assert json.loads((root / "gates.json").read_text())["min_tests"] == 999  # los umbrales no retroceden
    assert (root / "learning" / "incidents.jsonl").read_text() == "evidencia NUEVA\n"
    (root / "releases" / "STABLE").write_text(json.dumps({"release_id": m["release_id"], "approver": "impostor"}))
    with pytest.raises(IntegrityError):
        rel.rollback(root)  # un STABLE escrito a mano no vale


def test_stable_cannot_move_to_an_older_snapshot(tmp_path):
    (tmp_path / "p").mkdir()
    root = mini_project(tmp_path / "p")
    key = HybridSigPrivateKey.generate()
    m1, _ = snap(root, key)
    (root / "qce" / "m.py").write_text("def f(x):\n    return True\n")
    m2, _ = snap(root, key)
    assert m2["sequence"] > m1["sequence"]
    rel.mark_stable(root, m2["release_id"], "humano")
    with pytest.raises(QCEError, match="downgrade"):
        rel.mark_stable(root, m1["release_id"], "humano")


# ---- H5: QKD no recupera la confianza solo ----------------------------------------------------------------------------
def test_identity_proof_does_not_restore_trust_without_human_approval(tmp_path):
    from tests.test_qkd_adapters import attach, build
    broker, dev, link, reg, *_ = build(tmp_path)
    attach(broker, dev)
    reg.set_untrusted("devA", "comprometido")
    with pytest.raises(QKDDeviceError) as e:
        dev.authenticate_device()  # misma clave de identidad: antes volvía a TRUSTED
    assert e.value.category is ErrorCategory.DEVICE_UNTRUSTED and not reg.is_trusted("devA")
    with pytest.raises(PolicyViolation):
        reg.approve("devA", "  ")
    reg.approve("devA", "darwin", firmware="SIM-1.0")
    dev.authenticate_device()
    assert reg.is_trusted("devA")


def test_new_firmware_needs_review_and_approval_records_the_verified_firmware(tmp_path):
    from tests.test_qkd_adapters import attach, build
    from qce.qkd.contract import DeviceEvent
    broker, dev, link, reg, *_ = build(tmp_path)
    attach(broker, dev)
    dev.handle_device_event(DeviceEvent("firmware_changed", {"version": "EVIL-FW"}))
    with pytest.raises(QKDDeviceError):
        dev.authenticate_device()
    reg.approve("devA", "darwin", firmware="EVIL-FW")
    dev.authenticate_device()
    assert reg.get("devA").firmware_version == "EVIL-FW"


# ---- H9: una clave = una identidad; un veto bloquea -------------------------------------------------------------------
def test_one_key_cannot_hold_three_roles_and_a_reject_vetoes(tmp_path):
    k = HybridSigPrivateKey.generate()
    approvals.register(tmp_path, "implementer", "impl-bot", k.public_bytes)
    with pytest.raises(QCEError, match="misma clave"):
        approvals.register(tmp_path, "reviewer", "rev-bot", k.public_bytes)
    with pytest.raises(QCEError, match="misma clave"):
        approvals.register(tmp_path, "approver", "HUMAN-darwin", k.public_bytes)
    with pytest.raises(QCEError, match="rotación"):
        approvals.register(tmp_path, "implementer", "impl-bot", HybridSigPrivateKey.generate().public_bytes)
    r1, r2 = HybridSigPrivateKey.generate(), HybridSigPrivateKey.generate()
    approvals.register(tmp_path, "reviewer", "r1", r1.public_bytes)
    approvals.register(tmp_path, "reviewer", "r2", r2.public_bytes)
    approvals.sign_statement(tmp_path, r1, "reviewer", "r1", "R", "accept")
    assert approvals.valid_statements(tmp_path, "R", "reviewer") == ["r1"]
    approvals.sign_statement(tmp_path, r2, "reviewer", "r2", "R", "reject")
    assert approvals.valid_statements(tmp_path, "R", "reviewer") == []  # un 'reject' válido bloquea


def test_statement_signature_is_bound_to_its_signer(tmp_path):
    a, b = HybridSigPrivateKey.generate(), HybridSigPrivateKey.generate()
    approvals.register(tmp_path, "reviewer", "ana", a.public_bytes)
    approvals.register(tmp_path, "reviewer", "beto", b.public_bytes)
    f = approvals.sign_statement(tmp_path, a, "reviewer", "ana", "R", "accept")
    forged = json.loads(f.read_text())
    forged["signer"] = "beto"  # reutilizar la firma de ana a nombre de beto
    (tmp_path / "reviews" / "R.reviewer.beto.json").write_text(json.dumps(forged))
    assert approvals.valid_statements(tmp_path, "R", "reviewer") == ["ana"]


# ---- H10: handshake ---------------------------------------------------------------------------------------------------------
def test_low_order_x25519_point_gives_qce_error_not_valueerror():
    k = HybridKemPrivateKey.generate()
    _, ct = hybrid_encapsulate(k.public_bytes)
    with pytest.raises(AuthenticationFailure):
        k.decapsulate(b"\x00" * 32 + ct[32:])


def test_server_failed_finish_closes_cleanly_and_success_erases_ephemeral_key():
    ident = HybridSigPrivateKey.generate()
    c, s = ClientHandshake(ident.public_bytes), ServerHandshake(ident)
    m3 = c.on_server_hello(s.on_client_hello(c.start()))
    with pytest.raises(QCEError):
        s.on_client_finish(pack(T_CF, [b"\x00" * 1120, b"m" * 32]))
    assert s._kem is None
    with pytest.raises(QCEError):  # antes: AttributeError ajeno
        s.on_client_finish(m3)
    c, s = ClientHandshake(ident.public_bytes), ServerHandshake(ident)
    m4, _ = s.on_client_finish(c.on_server_hello(s.on_client_hello(c.start())))
    assert s._kem is None  # secreto hacia adelante observable


# ---- H11: vault ------------------------------------------------------------------------------------------------------------------
def test_vault_rejects_huge_or_non_power_of_two_scrypt_n_before_deriving(tmp_path):
    ks = KeyStore()
    ks.create(Purpose.ENCRYPT, 10)
    p = tmp_path / "v.bin"
    vault.save(ks, p, "frase-larga", n=2**14)
    import struct
    raw = bytearray(p.read_bytes())
    for bad in (2**20, 2**22, 3 * 2**14 + 1, 2**13):
        raw[13:17] = struct.pack(">I", bad)
        q = tmp_path / f"v{bad}.bin"
        q.write_bytes(bytes(raw))
        with pytest.raises(IntegrityError):
            vault.load(q, "frase-larga")


# ---- H14: rotate ----------------------------------------------------------------------------------------------------------------------
def test_rotating_a_revoked_key_leaves_no_orphan_active_key():
    ks = KeyStore()
    kid = ks.create(Purpose.ENCRYPT, 100)
    ks.activate(kid)
    ks.revoke(kid, "x")
    n = len(ks.all_ids())
    with pytest.raises(KeyStateError):
        ks.rotate(kid, 100)
    assert len(ks.all_ids()) == n and not any(ks.info(k).state is State.ACTIVE for k in ks.all_ids())


def test_revoked_key_with_resurrected_material_is_still_refused():
    ks = KeyStore()
    kid = ks.create(Purpose.ENCRYPT, 100)
    ks.activate(kid)
    ks.revoke(kid, "x")
    ks.info(kid).secret = bytearray(b"k" * 32)  # estado inconsistente (p. ej. vault manipulado)
    with pytest.raises(KeyStateError):
        ks.protect(kid, b"x")
    with pytest.raises(KeyStateError):
        ks.use(kid, Purpose.ENCRYPT, "unprotect")


# ---- H7: libro de incidentes y G4 ------------------------------------------------------------------------------------------------------
def test_incident_cannot_be_born_resolved_or_confirmed_nor_inject_pytest_options(tmp_path):
    L = Ledger(tmp_path / "i.jsonl")
    for bad in (dict(status="resuelto"), dict(lesson_state="CONFIRMED"), dict(confidence="CONFIRMADA"), dict(severity="x"),
                dict(reproduction_test="--collect-only"), dict(reproduction_test="tests/../../etc/x.py")):
        with pytest.raises(QCEError):
            L.open(Incident(f"INC-{abs(hash(str(bad))) % 999}", "v", "m", "s", **bad))
    L.open(Incident("INC-1", "v", "m", "s", reproduction_test="tests/t.py::test_x"))
    with pytest.raises(QCEError):
        L.update("INC-1", reproduction_test="--co")


def test_g4_treats_skipped_test_as_no_evidence(tmp_path):
    root = mini_project(tmp_path)
    (root / "tests" / "test_skip.py").write_text("import pytest\n\n\n@pytest.mark.skip\ndef test_s():\n    pass\n")
    L = Ledger(root / "learning" / "incidents.jsonl")
    L.open(Incident("INC-1", "v", "m", "s", severity="media", reproduction_test="tests/test_skip.py::test_s"))
    L.update("INC-1", status="resuelto", tests_run=["x"])
    rep = gates.evaluate(root, version="t", run_mutation=False, run_dep_audit=False)
    g4 = next(g for g in rep["gates"] if g["gate"].startswith("G4"))
    assert g4["status"] == "fail"  # rc=0 pero 0 pruebas realmente superadas


def test_g4_treats_zero_executed_tests_as_failure(tmp_path):
    root = mini_project(tmp_path)
    L = Ledger(root / "learning" / "incidents.jsonl")
    L.open(Incident("INC-1", "v", "m", "s", severity="media", reproduction_test="tests/test_m.py::test_no_existe"))
    L.update("INC-1", status="resuelto", tests_run=["x"])
    rep = gates.evaluate(root, version="t", run_mutation=False, run_dep_audit=False)
    g4 = next(g for g in rep["gates"] if g["gate"].startswith("G4"))
    assert g4["status"] == "fail" and "INC-1" in g4["evidence"]["regressed"]


# ---- H12/H13 -----------------------------------------------------------------------------------------------------------------------------
def test_chainlog_is_safe_under_concurrent_appends(tmp_path):
    log = ChainLog(tmp_path / "c.jsonl")
    ts = [threading.Thread(target=lambda i=i: [log.append({"t": i, "n": n}) for n in range(15)]) for i in range(4)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert log.verify() == 60


def test_sanitize_catches_base64_keys_short_hex_and_dict_keys():
    import base64, os
    k = os.urandom(32)
    out = json.dumps(sanitize({"b64": base64.b64encode(k).decode(), "url": base64.urlsafe_b64encode(k).decode().rstrip("="),
                               "hex": k[:16].hex(), base64.b64encode(k).decode(): "x"}))
    assert base64.b64encode(k).decode() not in out and k[:16].hex() not in out and base64.urlsafe_b64encode(k).decode().rstrip("=") not in out


# ---- H15 --------------------------------------------------------------------------------------------------------------------------------
def test_scanners_see_from_imports_and_nested_dirs_named_like_skipped_ones(tmp_path):
    (tmp_path / "qce" / "releases").mkdir(parents=True)
    (tmp_path / "qce" / "a.py").write_text("from random import randbytes\nfrom hashlib import md5\nmd5(b'')\n")
    (tmp_path / "qce" / "releases" / "b.py").write_text("eval('1')\n")
    (tmp_path / "x.pem").write_text('password = "hunter2hunter2hunter2"\n')
    rules = {(f.path, f.rule) for f in scanners.scan_misuse(tmp_path)}
    assert ("qce/a.py", "weak-random-import") in rules and ("qce/a.py", "weak-hash") in rules
    assert ("qce/releases/b.py", "unsafe-deserialization") in rules
    assert any(f.path == "x.pem" for f in scanners.scan_secrets(tmp_path))


def test_sanitize_does_not_destroy_long_readable_identifiers():
    """INC-0008: el redactor de base64 convertía nombres de prueba largos en [REDACTED-B64] y rompía las referencias de regresión."""
    name = "tests/test_audit_findings.py::test_ratchet_survives_repeated_evaluation_with_weakened_thresholds"
    assert sanitize(name) == name
    assert sanitize({"reproduction_test": name})["reproduction_test"] == name


def test_gate_g1_blocks_when_dependency_hashes_or_sbom_are_missing_or_incoherent(tmp_path):
    root = mini_project(tmp_path)
    kw = dict(version="t", run_mutation=False, run_dep_audit=False)
    g1 = lambda: next(g for g in gates.evaluate(root, **kw)["gates"] if g["gate"].startswith("G1"))      # noqa: E731
    base = g1()
    assert base["status"] == "pass" and "hashes y SBOM coherentes" in base["detail"]                     # el estado base no se bloquea por la cadena de suministro
    (root / "requirements.hashes.txt").unlink()
    r = g1()
    assert r["status"] == "blocked" and "requirements.hashes.txt" in r["detail"]
    shutil.copy2(ROOT / "requirements.hashes.txt", root / "requirements.hashes.txt")
    (root / "sbom.cdx.json").write_text(json.dumps({"components": []}))
    r = g1()
    assert r["status"] == "blocked" and "sbom.cdx.json" in r["detail"]
