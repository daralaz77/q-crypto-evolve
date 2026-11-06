"""El límite de tiempo del arnés de mutación depende de lo que tarda la línea base (y no de un valor fijo).

Contexto real: con 883 pruebas, UNA ejecución de la batería en el sandbox tardaba 114 s frente a un límite fijo de 120 s, y la prueba de mutación lanza 6 a la vez. Un tiempo agotado se cuenta como
«detectado», así que la lentitud se podía confundir con detección (y el mutante canario, que no cambia nada, salió «detectado»: el arnés se negó a dar un resultado en la puerta G3).
"""
import subprocess
from types import SimpleNamespace

import pytest

from qce.evolve import gates, mutation
from tests.test_audit_findings import mini_project
from tests.test_gates_gaps import g3, mut_result


@pytest.fixture
def root(tmp_path):
    (tmp_path / "p").mkdir()
    return mini_project(tmp_path / "p")


# ---- el cálculo del límite -----------------------------------------------------------------------------------------------
@pytest.mark.parametrize("baseline, floor, expected", [
    (0, 120, 120), (10, 120, 120), (24, 120, 120),            # batería rápida: manda el mínimo
    (24.1, 120, 121), (30, 120, 150), (114, 120, 570),        # el caso real: 114 s de línea base → 570 s por mutante
    (114, 900, 900),                                          # un mínimo mayor que el escalado se respeta
    (0.2, 1, 1), (0.21, 1, 2),                                # 5 × 0,2 = 1 s exactos; 5 × 0,21 = 1,05 → redondea hacia arriba
])
def test_per_mutant_timeout_is_the_larger_of_the_floor_and_five_times_the_baseline(baseline, floor, expected):
    assert mutation.effective_timeout(baseline, floor) == expected
    assert mutation.TIMEOUT_FACTOR == 5


def test_a_slower_baseline_never_lowers_the_timeout():
    values = [mutation.effective_timeout(b, 120) for b in range(0, 400, 7)]
    assert values == sorted(values) and values[0] >= 120


# ---- run_mutants con el tiempo y pytest simulados -----------------------------------------------------------------------------------
class Fake:
    """Doble de `_pytest` y del reloj: la 1.ª llamada es la línea base; las siguientes, los mutantes (por el nombre del archivo mutado)."""
    def __init__(self, baseline_s=30.0, behaviour=None):
        self.now, self.baseline_s, self.calls = 0.0, baseline_s, []
        self.behaviour = behaviour or {}

    def clock(self):
        return self.now

    def pytest(self, work, timeout):
        self.calls.append(timeout)
        if len(self.calls) == 1:
            self.now += self.baseline_s
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        src = (work / "qce" / "m.py").read_text()
        kind = "canary" if "(x in (1, 2))" in src else "real"
        action = self.behaviour.get(kind, 1 if kind == "real" else 0)
        if action == "timeout":
            raise subprocess.TimeoutExpired("pytest", timeout)
        return SimpleNamespace(returncode=action, stdout="", stderr="")


def patch(monkeypatch, fake):
    monkeypatch.setattr(mutation, "_pytest", fake.pytest)
    monkeypatch.setattr(mutation, "_clock", fake.clock)
    monkeypatch.setattr(mutation, "MUTANTS", [
        mutation.Mutant("real", "qce/m.py", (("return True", "return False"),), "g"),
        mutation.Mutant("CANARY-noop", "qce/m.py", (("if x in (1, 2):", "if (x in (1, 2)):"),), "g", "canary"),
    ])


def test_mutants_run_with_the_scaled_timeout_and_the_baseline_with_a_generous_one(root, monkeypatch):
    fake = Fake(baseline_s=30.0)
    patch(monkeypatch, fake)
    r = mutation.run_mutants(root)
    assert fake.calls[0] == mutation.BASELINE_TIMEOUT_S                       # la línea base no se ahoga con 120 s
    assert fake.calls[1:] == [150, 150]                                       # 30 s × 5, no el 120 fijo
    assert r["baseline_seconds"] == 30.0 and r["timeout_s"] == 150 and r["timed_out"] == []
    assert r["canary_ok"] is True and r["score"] == 1.0 and r["killed"] == 1


def test_a_fast_baseline_keeps_the_caller_floor(root, monkeypatch):
    fake = Fake(baseline_s=2.0)
    patch(monkeypatch, fake)
    r = mutation.run_mutants(root, timeout=200)
    assert fake.calls[1:] == [200, 200] and r["timeout_s"] == 200


def test_the_baseline_uses_the_caller_timeout_when_it_is_larger_than_the_cap(root, monkeypatch):
    fake = Fake()
    patch(monkeypatch, fake)
    mutation.run_mutants(root, timeout=5000)
    assert fake.calls[0] == 5000


def test_a_mutant_that_times_out_counts_as_detected_but_is_listed_as_timed_out(root, monkeypatch):
    fake = Fake(behaviour={"real": "timeout"})
    patch(monkeypatch, fake)
    r = mutation.run_mutants(root)
    assert r["killed"] == 1 and r["survivors"] == [] and r["timed_out"] == ["real"]
    by = {d["name"]: d for d in r["detail"]}
    assert by["real"]["timed_out"] is True and by["real"]["killed"] is True and by["CANARY-noop"]["timed_out"] is False


def test_a_mutant_killed_by_a_failing_test_is_not_listed_as_timed_out(root, monkeypatch):
    patch(monkeypatch, Fake())
    assert mutation.run_mutants(root)["timed_out"] == []


def test_a_canary_that_times_out_is_reported_as_slowness_not_as_detection(root, monkeypatch):
    patch(monkeypatch, Fake(baseline_s=30.0, behaviour={"canary": "timeout"}))
    with pytest.raises(RuntimeError, match=r"canario .* AGOTÓ el tiempo \(150 s; la línea base tardó 30 s\)") as e:
        mutation.run_mutants(root)
    assert "lentitud del equipo, no detección" in str(e.value)


def test_a_canary_killed_by_a_failing_test_keeps_the_original_message(root, monkeypatch):
    patch(monkeypatch, Fake(behaviour={"canary": 1}))
    with pytest.raises(RuntimeError, match="fue 'detectado'") as e:
        mutation.run_mutants(root)
    assert "AGOTÓ" not in str(e.value)


def test_a_baseline_that_never_finishes_says_the_suite_is_hung_not_a_bare_timeout(root, monkeypatch):
    def hung(work, timeout):
        raise subprocess.TimeoutExpired("pytest", timeout)
    monkeypatch.setattr(mutation, "_pytest", hung)
    with pytest.raises(RuntimeError, match=r"la línea base del sandbox no terminó en 1800 s"):
        mutation.run_mutants(root)


def test_a_red_baseline_is_still_refused(root, monkeypatch):
    monkeypatch.setattr(mutation, "_pytest", lambda w, t: SimpleNamespace(returncode=1, stdout="rojo", stderr=""))
    with pytest.raises(RuntimeError, match="línea base del sandbox NO es verde"):
        mutation.run_mutants(root)


# ---- de punta a punta, con pytest y reloj reales, en un proyecto mínimo -----------------------------------------------------------------------
def test_real_run_on_a_tiny_project_reports_its_timing_fields(root, monkeypatch):
    monkeypatch.setattr(mutation, "MUTANTS", [
        mutation.Mutant("real", "qce/m.py", (("return True", "return False"),), "g"),
        mutation.Mutant("CANARY-noop", "qce/m.py", (("if x in (1, 2):", "if (x in (1, 2)):"),), "g", "canary"),
    ])
    r = mutation.run_mutants(root)
    assert r["canary_ok"] is True and r["score"] == 1.0 and r["timed_out"] == []
    assert r["baseline_seconds"] > 0 and r["timeout_s"] >= 120
    assert all("timed_out" in d for d in r["detail"])


# ---- la puerta G3 expone los datos ---------------------------------------------------------------------------------------------------------------
def test_gate_g3_evidence_includes_the_timeout_figures(root, monkeypatch):
    g = g3(root, monkeypatch, mut=mut_result(baseline_seconds=114.0, timeout_s=570, timed_out=["x"]))
    assert g.status == "pass"
    assert g.evidence["mutation"]["baseline_seconds"] == 114.0 and g.evidence["mutation"]["timeout_s"] == 570
    assert g.evidence["mutation"]["timed_out"] == ["x"]


def test_gate_g3_still_works_with_a_result_that_lacks_the_new_fields(root, monkeypatch):
    g = g3(root, monkeypatch)                                                  # `mut_result()` no trae los campos nuevos
    assert g.status == "pass" and g.evidence["mutation"]["timed_out"] is None
    assert gates.CRITICAL                                                       # el módulo sigue importando sin cambios
