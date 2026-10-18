"""Pruebas de las herramientas de evolución: si el vigilante falla, nada de lo demás vale."""
import json

import pytest

from qce.core.errors import IntegrityError, QCEError
from qce.evolve import approvals
from qce.learning.ledger import Incident, Ledger
from qce.pqc.hybrid import HybridSigPrivateKey
from qce.recovery import release as rel
from qce.security import scanners


# ---- libro de incidentes -------------------------------------------------------------------
def test_ledger_refuses_resolution_without_reproduction_and_tests(tmp_path):
    L = Ledger(tmp_path / "i.jsonl")
    L.open(Incident("INC-1", "v", "m", "síntoma"))
    with pytest.raises(QCEError):
        L.update("INC-1", status="resuelto")
    with pytest.raises(QCEError):
        L.update("INC-1", status="resuelto", reproduction_test="tests/t.py::x")
    L.update("INC-1", status="resuelto", reproduction_test="tests/t.py::x", tests_run=["ok"])


def test_lesson_confirmation_needs_independent_evidence(tmp_path):
    L = Ledger(tmp_path / "i.jsonl")
    L.open(Incident("INC-1", "v", "m", "s", reproduction_test="tests/t.py::x"))
    with pytest.raises(QCEError):
        L.update("INC-1", lesson_state="CONFIRMED")
    L.update("INC-1", lesson_state="CONFIRMED", independent_evidence=True)


def test_level3_needs_named_human_approver(tmp_path):
    L = Ledger(tmp_path / "i.jsonl")
    L.open(Incident("INC-1", "v", "m", "s", repair_level=3))
    with pytest.raises(QCEError):
        L.update("INC-1", approval="aprobado")
    L.update("INC-1", approval="aprobado", approver="darwin")


def test_ledger_detects_recurring_root_cause_and_blockers(tmp_path):
    L = Ledger(tmp_path / "i.jsonl")
    for i in (1, 2):
        L.open(Incident(f"INC-{i}", "v", "m", "s", root_cause_category="codigo", severity="alta"))
    assert L.patterns() and L.open_blockers() == ["INC-1", "INC-2"]
    with pytest.raises(QCEError):
        L.open(Incident("INC-1", "v", "m", "dup"))


def test_ledger_never_stores_secrets(tmp_path):
    L = Ledger(tmp_path / "i.jsonl")
    L.open(Incident("INC-1", "v", "m", "clave filtrada: " + "ab" * 40 + " password=hunter2"))
    raw = (tmp_path / "i.jsonl").read_text()
    assert "hunter2" not in raw and "abab" not in raw


def test_ledger_tamper_detected(tmp_path):
    L = Ledger(tmp_path / "i.jsonl")
    L.open(Incident("INC-1", "v", "m", "s"))
    L.update("INC-1", status="reproducido")
    lines = (tmp_path / "i.jsonl").read_text().splitlines()
    e = json.loads(lines[0])
    e["body"] = e["body"].replace("abierto", "resuelto")
    (tmp_path / "i.jsonl").write_text("\n".join([json.dumps(e)] + lines[1:]) + "\n")
    with pytest.raises(IntegrityError):
        L.log.verify()


# ---- niveles y clasificación ---------------------------------------------------------------
def test_change_levels():
    assert change_level_of(["README.md"]) == 1
    assert change_level_of(["README.md", "qce/protocols/session.py"]) == 2
    assert change_level_of(["qce/protocols/session.py", "gates.json"]) == 3  # tocar los controles = nivel 3
    assert change_level_of(["learning/incidents.jsonl"]) == 3  # borrar/alterar auditoría


def change_level_of(paths):
    return rel.change_level(paths)


def test_failure_classifier():
    assert rel.classify_failure("ModuleNotFoundError: x")[0] == "dependencia"
    assert rel.classify_failure("Failed: DID NOT RAISE")[0] == "codigo"
    assert rel.classify_failure("???")[0] == "desconocida"


# ---- versiones y reversión -----------------------------------------------------------------
def _mini_project(tmp_path):
    (tmp_path / "qce").mkdir()
    (tmp_path / "qce" / "a.py").write_text("X = 1\n")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_a.py").write_text("def test_a(): pass\n")
    (tmp_path / "requirements.lock").write_text("cryptography==50.0.2\n")
    (tmp_path / "learning").mkdir()
    (tmp_path / "learning" / "incidents.jsonl").write_text("evidencia\n")
    return tmp_path


def test_release_snapshot_rollback_preserves_evidence_and_detects_tamper(tmp_path):
    root = _mini_project(tmp_path)
    m = rel.build_manifest(root, "1.0", {}, [], {})
    rel.save_release(root, m)
    with pytest.raises(QCEError):
        rel.mark_stable(root, m["release_id"], approver="")
    human = HybridSigPrivateKey.generate()
    approvals.register(root, "approver", "humano", human.public_bytes)
    with pytest.raises(QCEError):  # nombrar a un humano sin su firma no basta
        rel.mark_stable(root, m["release_id"], approver="humano")
    approvals.sign_statement(root, human, "approver", "humano", m["release_id"], "accept")
    rel.mark_stable(root, m["release_id"], approver="humano")
    (root / "qce" / "a.py").write_text("X = 999  # roto\n")
    (root / "learning" / "incidents.jsonl").write_text("evidencia NUEVA\n")
    restored = rel.rollback(root)
    assert (root / "qce" / "a.py").read_text() == "X = 1\n"
    assert (root / "learning" / "incidents.jsonl").read_text() == "evidencia NUEVA\n"  # la evidencia no se revierte
    assert "qce/a.py" in restored
    (root / "releases" / m["release_id"] / "src" / "qce" / "a.py").write_text("X = 666\n")
    with pytest.raises(IntegrityError):
        rel.rollback(root)  # snapshot manipulado: no se restaura


def test_release_id_changes_with_any_code_change(tmp_path):
    root = _mini_project(tmp_path)
    a = rel.build_manifest(root, "1", {}, [], {})["release_id"]
    (root / "qce" / "a.py").write_text("X = 2\n")
    assert rel.build_manifest(root, "1", {}, [], {})["release_id"] != a


# ---- revisión independiente y autorización firmadas ------------------------------------------
def test_signed_statements_bind_role_signer_and_exact_code(tmp_path):
    impl, rev, human = (HybridSigPrivateKey.generate() for _ in range(3))
    approvals.register(tmp_path, "implementer", "agente-impl", impl.public_bytes)
    approvals.register(tmp_path, "reviewer", "agente-rev", rev.public_bytes)
    approvals.register(tmp_path, "approver", "darwin", human.public_bytes)
    approvals.sign_statement(tmp_path, rev, "reviewer", "agente-rev", "R1", "accept")
    assert approvals.valid_statements(tmp_path, "R1", "reviewer") == ["agente-rev"]
    assert approvals.valid_statements(tmp_path, "R2", "reviewer") == []  # otro código: no vale
    # firma de otra clave haciéndose pasar por el revisor
    approvals.sign_statement(tmp_path, impl, "reviewer", "agente-rev", "R3", "accept")
    assert approvals.valid_statements(tmp_path, "R3", "reviewer") == []
    # un implementador no puede firmar como aprobador humano
    approvals.sign_statement(tmp_path, impl, "approver", "agente-impl", "R4", "accept")
    assert approvals.valid_statements(tmp_path, "R4", "approver") == []
    # un veredicto "reject" nunca cuenta
    approvals.sign_statement(tmp_path, rev, "reviewer", "agente-rev", "R5", "reject")
    assert approvals.valid_statements(tmp_path, "R5", "reviewer") == []


# ---- escáneres ---------------------------------------------------------------------------------
def test_secret_scanner_finds_planted_secrets(tmp_path):
    (tmp_path / "x.py").write_text('API_KEY = "sk_live_' + "a1B2c3D4" * 4 + '"\n-----BEGIN PRIVATE KEY-----\n')
    rules = {f.rule for f in scanners.scan_secrets(tmp_path)}
    assert "secret:pem-private-key" in rules and "secret:generic-secret-assign" in rules


def test_misuse_scanner_flags_planted_bad_crypto(tmp_path):
    pkg = tmp_path / "qce"
    pkg.mkdir()
    (pkg / "bad.py").write_text(
        "import random, hashlib\n"
        "def f(mac, expected_mac, x):\n"
        "    assert x\n"
        "    hashlib.md5(b'')\n"
        "    return mac == expected_mac\n"
        "requests.get(u, verify=False)\n")
    rules = {f.rule for f in scanners.scan_misuse(tmp_path)}
    assert {"weak-random-import", "weak-hash", "assert-in-library", "non-constant-time-compare", "disabled-validation"} <= rules
