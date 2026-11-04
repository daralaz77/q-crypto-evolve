"""Pruebas de la demostración del ciclo fallo → reparación → regresión → reversión (`qce/evolve/demo.py`).

La demo real copia el proyecto a un laboratorio y ejecuta la batería COMPLETA varias veces dentro de la copia (decenas de minutos). Aquí se sustituye SOLO el
lanzamiento de `pytest` (el de la demo y el de la puerta G2/G4) por un doble fiel al ESTADO de la copia: falla si y solo si el defecto controlado está aplicado
en `session.py`. Todo lo demás es real: la copia, el libro de incidentes, el flujo de tareas, las firmas, el release, la reversión, el vault y las puertas.
La ejecución real de punta a punta es opcional: `QCE_DEMO_FULL=1 pytest tests/test_demo.py -k real`.
"""
import hashlib
import json
import os
from pathlib import Path

import pytest

from qce.core.errors import QCEError
from qce.evolve import demo, gates

ROOT = Path(__file__).resolve().parent.parent
SESSION = "qce/protocols/session.py"


# La comprobación 23 de la demo reutiliza el historial REAL de incidentes del proyecto (`learning/`); el sandbox de la prueba de mutación no lo copia.
needs_history = pytest.mark.skipif(not (ROOT / "learning" / "incidents.jsonl").exists(),
                                   reason="sin learning/incidents.jsonl (p. ej. el sandbox de mutación) la comprobación 23 de la demo no puede cumplirse")


def fault_applied(root: Path) -> bool:
    s = (root / SESSION).read_text(encoding="utf-8")
    return all(new in s and old not in s for old, new in demo.FAULT.edits)


def fake_demo_pytest(root, *args):
    if fault_applied(root):
        return 1, "FAILED tests/test_session.py::test_client_rejects_impostor - AssertionError\n1 failed, 699 passed in 1.0s"
    return 0, "700 passed in 1.0s"


def fake_gate_pytest(root, args=None):
    return (1, 699, "1 failed") if fault_applied(root) else (0, 700, "700 passed")


@pytest.fixture
def faithful(monkeypatch):
    monkeypatch.setattr(demo, "_pytest", fake_demo_pytest)
    monkeypatch.setattr(gates, "_run_pytest", fake_gate_pytest)


def sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


@needs_history
@pytest.mark.skipif("qce-lab-" in str(ROOT), reason="dentro del laboratorio de la propia demo no se vuelve a ejecutar la demo")
def test_the_whole_cycle_runs_end_to_end_and_every_check_is_observed(faithful, tmp_path):
    watched = [f for f in (SESSION, "gates.json", "learning/incidents.jsonl", "learning/version_history.jsonl") if (ROOT / f).exists()]
    assert SESSION in watched                       # el código vigilado existe siempre (en el sandbox de mutación no hay carpeta learning/)
    before = {f: sha(ROOT / f) for f in watched}
    out = tmp_path / "salida"
    r = demo.run(ROOT, out)
    failed = [c for c in r["checks"] if not c["ok"]]
    assert r["all_ok"] and not failed, failed
    assert len(r["checks"]) == 25 and len(r["log"]) == 25 and all(line.startswith("[OK ]") for line in r["log"])
    assert [c["check"].split(".")[0] for c in r["checks"]] == [str(i) for i in range(1, 26)]        # nada se salta ni se repite
    assert all(c["observed"] for c in r["checks"])                                                  # cada comprobación trae su observación real
    saved = json.loads((out / "demo_latest.json").read_text(encoding="utf-8"))
    assert saved["all_ok"] is True and saved["checks"] == r["checks"] and "log" not in saved
    assert {"deteccion_a_incidente", "preparar_reparacion", "reversion", "total"} <= set(r["timings_s"])
    assert "hallazgo autónomo de fallos desconocidos" in r["not_demonstrated"] and "auditoría externa" in r["not_demonstrated"]
    # el proyecto real NO se modifica (todo ocurre en la copia temporal)
    assert {f: sha(ROOT / f) for f in before} == before


@pytest.mark.skipif("qce-lab-" in str(ROOT), reason="dentro del laboratorio de la propia demo no se vuelve a ejecutar la demo")
def test_the_demo_aborts_instead_of_claiming_success_when_the_fault_is_not_detected(monkeypatch, tmp_path):
    """Si las pruebas NO detectan el defecto controlado, no hay prueba de reproducción: el libro de incidentes lo rechaza y la demo aborta.
    Nunca se escribe un informe que diga que todo salió bien."""
    monkeypatch.setattr(demo, "_pytest", lambda root, *a: (0, "700 passed in 1.0s"))
    monkeypatch.setattr(gates, "_run_pytest", lambda root, args=None: (0, 700, "700 passed"))
    with pytest.raises(QCEError, match="CONFIRMADA requiere reproducción"):
        demo.run(ROOT, tmp_path / "salida")
    assert not (tmp_path / "salida" / "demo_latest.json").exists()


@needs_history
@pytest.mark.skipif("qce-lab-" in str(ROOT), reason="dentro del laboratorio de la propia demo no se vuelve a ejecutar la demo")
def test_one_failed_check_makes_all_ok_false_even_if_the_rest_of_the_cycle_works(monkeypatch, tmp_path):
    """La línea base (comprobación 1) falla pero el resto del ciclo sigue siendo coherente: el resultado global NO puede ser éxito."""
    calls = []

    def baseline_broken_once(root, *args):
        calls.append(1)
        if len(calls) == 1:
            return 1, "1 failed, 699 passed in 1.0s"
        return fake_demo_pytest(root, *args)
    monkeypatch.setattr(demo, "_pytest", baseline_broken_once)
    monkeypatch.setattr(gates, "_run_pytest", fake_gate_pytest)
    r = demo.run(ROOT, tmp_path / "salida")
    bad = [c["check"].split(".")[0] for c in r["checks"] if not c["ok"]]
    assert bad == ["1"] and r["all_ok"] is False
    assert json.loads((tmp_path / "salida" / "demo_latest.json").read_text(encoding="utf-8"))["all_ok"] is False


def test_apply_replaces_exactly_one_fragment_and_can_be_reversed(tmp_path):
    f = tmp_path / "m.py"
    f.write_text("a = 1\nb = 2\n", encoding="utf-8")
    demo._apply(f, [("a = 1", "a = 9")])
    assert f.read_text(encoding="utf-8") == "a = 9\nb = 2\n"
    demo._apply(f, [("a = 1", "a = 9")], reverse=True)
    assert f.read_text(encoding="utf-8") == "a = 1\nb = 2\n"


@pytest.mark.parametrize("content", ["x = 1\n", "a = 1\na = 1\n"], ids=["ausente", "ambiguo"])
def test_apply_refuses_a_fragment_that_is_missing_or_ambiguous_and_leaves_the_file_untouched(tmp_path, content):
    f = tmp_path / "m.py"
    f.write_text(content, encoding="utf-8")
    with pytest.raises(RuntimeError, match="fragmento no encontrado"):
        demo._apply(f, [("a = 1", "a = 9")])
    assert f.read_text(encoding="utf-8") == content


def test_hashlib_file_is_the_sha256_of_the_bytes(tmp_path):
    f = tmp_path / "x.bin"
    f.write_bytes(b"\x00hola")
    assert demo.hashlib_file(f) == hashlib.sha256(b"\x00hola").hexdigest()


def test_the_controlled_fault_exists_applies_once_and_is_a_single_line_change():
    s = (ROOT / SESSION).read_text(encoding="utf-8")
    assert all(s.count(old) == 1 for old, _ in demo.FAULT.edits)                # sigue siendo aplicable al código actual
    assert not fault_applied(ROOT)                                               # el código real NO tiene el defecto


def test_the_demo_subprocess_runs_pytest_with_a_clean_environment(monkeypatch, tmp_path):
    seen = {}

    class R:
        returncode, stdout, stderr = 0, "3 passed\n", ""
    monkeypatch.setattr(demo.subprocess, "run", lambda cmd, **kw: seen.update(cmd=cmd, **kw) or R())
    rc, out = demo._pytest(tmp_path, "-k", "algo")
    assert (rc, out) == (0, "3 passed\n")
    assert seen["cmd"][1:3] == ["-m", "pytest"] and seen["cmd"][-2:] == ["-k", "algo"] and "-x" in seen["cmd"]
    assert seen["cwd"] == tmp_path and seen["env"] == {"PYTHONPATH": str(tmp_path), "PATH": "/usr/bin:/bin"}   # entorno mínimo: sin secretos heredados
    assert seen["timeout"] == 900


@pytest.mark.skipif(os.environ.get("QCE_DEMO_FULL") != "1" or "qce-lab-" in str(ROOT), reason="ejecución real de punta a punta: define QCE_DEMO_FULL=1 (tarda decenas de minutos)")
def test_real_end_to_end_demo(tmp_path):
    r = demo.run(ROOT, tmp_path)
    assert r["all_ok"], [c for c in r["checks"] if not c["ok"]]
