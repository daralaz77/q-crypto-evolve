"""Huecos de cobertura de las puertas (`qce/evolve/gates.py`): ramas de bloqueo y de fallo que ninguna prueba ejercía.

Cada prueba afirma el ESTADO de la puerta (pass / fail / blocked / skipped), no solo que el código corra: una puerta que dice «pass» cuando no debe es el peor
fallo posible de este módulo. Las piezas externas (escáneres, mutación, pytest, firmas) se sustituyen por dobles que devuelven un resultado concreto; las puertas, el
libro de incidentes, las cadenas de registro y el cálculo del estado final son reales.
"""
import json

import pytest

from qce.core.chainlog import ChainLog
from qce.core.errors import QCEError
from qce.evolve import gates, mutation
from qce.evolve.gates import GateResult
from qce.evolve.workflow import Workflow
from qce.learning.ledger import Ledger
from qce.security import approvals, scanners
from tests.test_audit_findings import mini_project, mk


@pytest.fixture
def root(tmp_path):
    (tmp_path / "p").mkdir()
    return mini_project(tmp_path / "p")


def ctx(root, **kw):
    return gates._Ctx(root, gates.load_thresholds(root), Ledger(root / "learning" / "incidents.jsonl"),
                      ChainLog(root / "learning" / "version_history.jsonl"), **kw)


# ---- validación de umbrales -----------------------------------------------------------------------------------
GOOD = {"min_tests": 60, "min_mutation_score": 1.0, "max_open_high": 0, "min_mutants": 0, "max_declared_equivalent": 10}


@pytest.mark.parametrize("key, bad", [
    ("min_tests", 2.5),                 # un entero no puede ser fraccionario
    ("min_tests", float("nan")), ("min_tests", float("inf")), ("min_tests", True), ("min_tests", "60"), ("min_tests", None),
    ("min_tests", -1), ("min_mutation_score", 1.5), ("min_mutation_score", -0.1), ("max_open_high", 10**7),
])
def test_invalid_thresholds_are_refused_instead_of_silently_weakening_a_gate(key, bad):
    with pytest.raises(QCEError, match=f"umbral '{key}' inválido o ausente"):
        gates.validate_thresholds({**GOOD, key: bad})


def test_a_missing_threshold_is_refused_and_a_valid_set_passes_unchanged():
    assert gates.validate_thresholds(dict(GOOD)) == GOOD
    incomplete = {k: v for k, v in GOOD.items() if k != "min_tests"}
    with pytest.raises(QCEError, match="min_tests"):
        gates.validate_thresholds(incomplete)


def test_an_integer_valued_float_is_accepted_for_integer_thresholds():
    assert gates.validate_thresholds({**GOOD, "min_tests": 60.0})["min_tests"] == 60.0


def test_evaluate_blocks_with_a_clear_reason_when_gates_json_is_corrupt(root):
    (root / "gates.json").write_text("{no es json", encoding="utf-8")
    rep = gates.evaluate(root, version="t", run_mutation=False, run_dep_audit=False)
    assert rep["state"] == "BLOCKED" and rep["release_id"] == "" and "gates.json inválido" in rep["gates"][0]["detail"]


# ---- G1: integridad ---------------------------------------------------------------------------------------------------
def test_g1_blocks_when_the_task_log_was_tampered_with(root):
    wf = Workflow(root / "learning" / "tasks.jsonl")
    wf.create(mk())
    f = root / "learning" / "tasks.jsonl"
    original = f.read_text(encoding="utf-8")
    tampered = original.replace("criterio", "otro-criterio")
    assert tampered != original                                          # la alteración realmente cambió el registro
    f.write_text(tampered, encoding="utf-8")
    g = gates._g1_integrity(ctx(root))
    assert g.status == "blocked" and "registros de aprendizaje manipulados" in g.detail and gates.CRITICAL in g.detail


@pytest.mark.parametrize("stable_text", ["{no es json", "{}", json.dumps({"release_id": "no-existe"})],
                         ids=["json-invalido", "sin-release_id", "snapshot-inexistente"])
def test_g1_blocks_on_any_broken_stable_snapshot_pointer(root, stable_text):
    (root / "releases").mkdir()
    (root / "releases" / "STABLE").write_text(stable_text, encoding="utf-8")
    g = gates._g1_integrity(ctx(root))
    assert g.status == "blocked" and "snapshot estable no verifica" in g.detail


def test_g1_blocks_without_requirements_lock(root):
    (root / "requirements.lock").unlink()
    g = gates._g1_integrity(ctx(root))
    assert g.status == "blocked" and "falta requirements.lock" in g.detail


def test_g1_blocks_when_an_installed_dependency_differs_from_the_lock(root):
    lock = root / "requirements.lock"
    lock.write_text(lock.read_text(encoding="utf-8") + "\npaquete-que-no-existe==9.9.9\n", encoding="utf-8")
    g = gates._g1_integrity(ctx(root))
    assert g.status == "blocked" and "dependencia instalada difiere del lock: paquete-que-no-existe==9.9.9" in g.detail


@pytest.mark.parametrize("boot", ["conftest.py", "sitecustomize.py", "usercustomize.py"])
def test_g1_blocks_test_bootstrap_files_in_the_root(root, boot):
    (root / boot).write_text("import os\n", encoding="utf-8")
    g = gates._g1_integrity(ctx(root))
    assert g.status == "blocked" and boot in g.detail


# ---- G2: funcionalidad ----------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("rc, passed, status, fragment", [
    (1, 50, "fail", "pruebas fallidas"),
    (0, 3, "fail", "solo 3 pruebas < mínimo 60"),         # se borraron pruebas
    (0, 60, "pass", "60 pruebas superadas"),
])
def test_g2_only_passes_when_tests_pass_and_enough_of_them_ran(root, monkeypatch, rc, passed, status, fragment):
    monkeypatch.setattr(gates, "_run_pytest", lambda r, args=None: (rc, passed, "cola"))
    (root / "gates.json").write_text(json.dumps(GOOD), encoding="utf-8")
    c = ctx(root)
    g = gates._g2_functionality(c)
    assert g.status == status and fragment in g.detail and c.passed == passed
    assert (g.evidence == {"tail": "cola"}) == (rc != 0)


# ---- G3: seguridad --------------------------------------------------------------------------------------------------------------
def mut_result(**kw):
    base = {"total": 10, "scored": 10, "killed": 10, "score": 1.0, "survivors": [], "declared_equivalent": [], "seconds": 1.0, "canary_ok": True}
    return {**base, **kw}


def g3(root, monkeypatch, *, misuse=(), secrets=(), mut=None, deps=None, run_mutation=True, run_dep_audit=True, **th):
    (root / "gates.json").write_text(json.dumps({**GOOD, "min_tests": 1, "min_mutants": 0, **th}), encoding="utf-8")
    monkeypatch.setattr(scanners, "scan_misuse", lambda r: list(misuse))
    monkeypatch.setattr(scanners, "scan_secrets", lambda r: list(secrets))
    monkeypatch.setattr(scanners, "audit_dependencies", lambda r: deps or {"status": "limpia"})
    monkeypatch.setattr(mutation, "run_mutants", lambda r, only=None: mut or mut_result())
    return gates._g3_security(ctx(root, run_mutation=run_mutation, run_dep_audit=run_dep_audit))


F = lambda sev: scanners.Finding("regla", "a.py", 3, "d", sev)      # noqa: E731


def test_g3_passes_only_with_everything_clean_and_all_evidence_present(root, monkeypatch):
    g = g3(root, monkeypatch)
    assert g.status == "pass" and "mutación completa, dependencias limpias" in g.detail
    assert set(g.evidence) == {"misuse", "secrets", "mutation", "dependencies"}


@pytest.mark.parametrize("sev, status", [("critica", "fail"), ("alta", "fail"), ("media", "fail"), ("baja", "pass")])
def test_g3_misuse_below_medium_severity_does_not_fail_the_gate(root, monkeypatch, sev, status):
    g = g3(root, monkeypatch, misuse=[F(sev)])
    assert g.status == status and (status == "pass" or "1 malos usos criptográficos" in g.detail)
    assert g.evidence["misuse"] == (["a.py:3 regla"] if sev != "baja" else [])   # la evidencia solo recoge lo que cuenta (≥ media)


def test_g3_possible_secrets_block_even_if_everything_else_is_perfect(root, monkeypatch):
    g = g3(root, monkeypatch, secrets=[F("critica"), F("critica")])
    assert g.status == "blocked" and f"{gates.CRITICAL}: 2 posibles secretos" in g.detail


@pytest.mark.parametrize("mut, fragment", [
    (mut_result(score=0.9, survivors=["m1"]), "puntuación de mutación 0.9 < 1.0; supervivientes: ['m1']"),
    (mut_result(canary_ok=False), "el canario del arnés de mutación falta o fue 'detectado'"),
    (mut_result(scored=5), "solo 5 mutantes puntuables < mínimo 8"),
    (mut_result(declared_equivalent=["a", "b", "c"]), "3 mutantes declarados equivalentes > máximo 2"),
])
def test_g3_fails_on_each_mutation_weakness(root, monkeypatch, mut, fragment):
    g = g3(root, monkeypatch, mut=mut, min_mutants=8, max_declared_equivalent=2)
    assert g.status == "fail" and fragment in g.detail


@pytest.mark.parametrize("deps, fragment", [
    ({"status": "vulnerable", "vulnerabilities": ["CVE-1"]}, "dependencias vulnerables ['CVE-1']"),
    ({"status": "no_ejecutada", "reason": "sin red"}, "auditoría de dependencias no ejecutada (sin red)"),
])
def test_g3_blocks_on_vulnerable_or_unaudited_dependencies(root, monkeypatch, deps, fragment):
    g = g3(root, monkeypatch, deps=deps)
    assert g.status == "blocked" and fragment in g.detail and g.evidence["dependencies"] == deps


@pytest.mark.parametrize("kw, fragment", [
    ({"run_mutation": False}, "prueba de mutación no ejecutada"),
    ({"run_dep_audit": False}, "auditoría de dependencias omitida"),
])
def test_g3_missing_evidence_is_blocked_never_passed(root, monkeypatch, kw, fragment):
    g = g3(root, monkeypatch, **kw)
    assert g.status == "blocked" and "evidencia insuficiente" in g.detail and fragment in g.detail


def test_g3_blocked_wins_over_failed_but_reports_both_reasons(root, monkeypatch):
    g = g3(root, monkeypatch, misuse=[F("alta")], secrets=[F("critica")])
    assert g.status == "blocked" and "posibles secretos" in g.detail and "malos usos criptográficos" in g.detail


# ---- G4: regresión -----------------------------------------------------------------------------------------------------------------
class FakeLedger:
    def __init__(self, items):
        self.items = items

    def all(self):
        return self.items


def inc(i, **kw):
    return {"incident_id": f"INC-{i:04d}", "status": "resuelto", "severity": "media", "reproduction_test": "tests/test_x.py::test_a", **kw}


def g4(root, monkeypatch, items, pytest_result=(0, 1, ""), **th):
    (root / "gates.json").write_text(json.dumps({**GOOD, **th}), encoding="utf-8")
    c = ctx(root)
    c.ledger = FakeLedger(items)
    monkeypatch.setattr(gates, "_run_pytest", lambda r, args=None: pytest_result)
    return gates._g4_regression(c)


def test_g4_passes_and_counts_the_incidents_it_actually_reproduced(root, monkeypatch):
    g = g4(root, monkeypatch, [inc(1), inc(2), inc(3, status="abierto", severity="baja")])
    assert g.status == "pass" and g.evidence == {"checked": 2} and "2 incidentes históricos" in g.detail


@pytest.mark.parametrize("result, why", [((1, 5, ""), "la prueba falla"), ((0, 0, ""), "0 pruebas ejecutadas no es una regresión superada")])
def test_g4_a_resolved_incident_whose_test_fails_or_does_not_run_is_a_regression(root, monkeypatch, result, why):
    g = g4(root, monkeypatch, [inc(1)], pytest_result=result)
    assert g.status == "fail" and g.evidence["regressed"] == ["INC-0001"], why


def test_g4_a_resolved_incident_without_a_regression_test_is_not_resolved(root, monkeypatch):
    g = g4(root, monkeypatch, [inc(1, reproduction_test="")])
    assert g.status == "fail" and g.evidence["regressed"] == ["INC-0001"]


@pytest.mark.parametrize("ref", ["--collect-only", "../../etc/passwd", "tests/test_x.py::test_a; rm -rf /", ""],
                         ids=["inyeccion-de-opcion", "ruta-fuera", "inyeccion-de-shell", "vacia"])
def test_g4_an_unsafe_test_reference_counts_as_a_failed_regression_and_is_never_executed(root, monkeypatch, ref):
    ran = []
    (root / "gates.json").write_text(json.dumps(GOOD), encoding="utf-8")
    c = ctx(root)
    c.ledger = FakeLedger([inc(1, reproduction_test=ref)])
    monkeypatch.setattr(gates, "_run_pytest", lambda r, args=None: ran.append(args) or (0, 1, ""))
    g = gates._g4_regression(c)
    assert g.status == "fail" and g.evidence["regressed"] == ["INC-0001"] and ran == []


def test_g4_a_failure_to_launch_pytest_is_a_failed_regression_not_a_pass(root, monkeypatch):
    (root / "gates.json").write_text(json.dumps(GOOD), encoding="utf-8")
    c = ctx(root)
    c.ledger = FakeLedger([inc(1)])

    def boom(r, args=None):
        raise OSError("no se pudo lanzar")
    monkeypatch.setattr(gates, "_run_pytest", boom)
    g = gates._g4_regression(c)
    assert g.status == "fail" and g.evidence["regressed"] == ["INC-0001"]


@pytest.mark.parametrize("severity, max_open, status", [
    ("critica", 0, "blocked"), ("alta", 0, "blocked"), ("media", 0, "pass"), ("baja", 0, "pass"),
    ("alta", 1, "pass"),                                    # el umbral lo permite (y el trinquete de G1 impide aflojarlo)
])
def test_g4_open_serious_incidents_block_according_to_the_threshold(root, monkeypatch, severity, max_open, status):
    g = g4(root, monkeypatch, [inc(7, status="abierto", severity=severity, reproduction_test="")], max_open_high=max_open)
    assert g.status == status and (status == "pass" or "INC-0007" in g.detail)


def test_g4_blocked_has_priority_over_a_regression(root, monkeypatch):
    g = g4(root, monkeypatch, [inc(1), inc(2, status="abierto", severity="critica", reproduction_test="")], pytest_result=(1, 0, ""))
    assert g.status == "blocked" and "INC-0002" in g.detail


# ---- G5 / G6 y estado final ------------------------------------------------------------------------------------------------------------------
def statements(monkeypatch, **by_role):
    monkeypatch.setattr(approvals, "valid_statements", lambda r, rid, role: list(by_role.get(role, [])))


@pytest.mark.parametrize("impl, rev, status, fragment", [
    ([], [], "skipped", "sin declaración firmada del implementador"),
    ([], ["rev"], "skipped", "sin declaración firmada del implementador"),
    (["a"], [], "skipped", "agente distinto del implementador"),
    (["a"], ["a"], "skipped", "agente distinto del implementador"),          # autorrevisión
    (["a", "b"], ["a", "b"], "skipped", "agente distinto del implementador"),
    (["a"], ["a", "rev"], "pass", "['rev']"),
    (["a"], ["rev2", "rev1"], "pass", "['rev1', 'rev2']"),                    # ordenado, determinista
])
def test_g5_requires_a_reviewer_who_is_not_the_implementer(root, monkeypatch, impl, rev, status, fragment):
    statements(monkeypatch, implementer=impl, reviewer=rev)
    c = ctx(root)
    c.rid = "rid"
    g = gates._g5_independence(c)
    assert g.status == status and fragment in g.detail


@pytest.mark.parametrize("approvers, status", [([], "skipped"), (["humano"], "pass")])
def test_g6_requires_a_valid_human_authorization_for_this_exact_code(root, monkeypatch, approvers, status):
    statements(monkeypatch, approver=approvers)
    c = ctx(root)
    c.rid = "rid"
    g = gates._g6_authorization(c)
    assert g.status == status and (status == "skipped" or "['humano']" in g.detail)


def results(g1="pass", g2="pass", g3="pass", g4="pass", g5="pass", g6="pass"):
    names = ("G1-INTEGRIDAD", "G2-FUNCIONALIDAD", "G3-SEGURIDAD", "G4-REGRESION", "G5-INDEPENDENCIA", "G6-AUTORIZACION")
    return [GateResult(n, s, "") for n, s in zip(names, (g1, g2, g3, g4, g5, g6), strict=True)]


@pytest.mark.parametrize("kw, state", [
    ({}, "RELEASE_APPROVED"),
    ({"g6": "skipped"}, "VERIFIED"),
    ({"g6": "fail"}, "VERIFIED"),                          # G6 nunca bloquea por sí sola: solo falta la autorización
    ({"g5": "skipped", "g6": "skipped"}, "REVIEW_REQUIRED"),
    ({"g5": "skipped"}, "REVIEW_REQUIRED"),                # sin revisión independiente no hay VERIFIED aunque haya autorización
    ({"g2": "fail"}, "FAILED"),
    ({"g1": "fail", "g5": "skipped"}, "FAILED"),
    ({"g3": "blocked"}, "BLOCKED"),
    ({"g3": "blocked", "g2": "fail"}, "BLOCKED"),          # bloqueado manda sobre fallido
    ({"g4": "blocked", "g5": "pass", "g6": "pass"}, "BLOCKED"),
])
def test_final_state_is_the_most_restrictive_consequence_of_the_gates(kw, state):
    assert gates._final_state(results(**kw)) == state


# ---- una puerta que revienta es un fallo, nunca un pase ---------------------------------------------------------------------------------------
def test_a_crashing_gate_is_reported_as_failed_and_the_overall_state_cannot_be_good(root, monkeypatch):
    def broken(c):
        raise RuntimeError("explotó la herramienta")
    monkeypatch.setattr(gates, "_g2_functionality", broken)
    monkeypatch.setattr(gates, "_run_pytest", lambda r, args=None: (0, 99, ""))
    rep = gates.evaluate(root, version="t", run_mutation=False, run_dep_audit=False)
    g2 = next(g for g in rep["gates"] if g["gate"].startswith("G2"))
    assert g2["status"] == "fail" and "error interno de la puerta: RuntimeError: explotó la herramienta" in g2["detail"]
    assert rep["state"] in ("FAILED", "BLOCKED") and rep["metrics"]["tests_passed"] is None
