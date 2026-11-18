"""Ronda 6 de auditoría (2026-11-17): el registro encadenado y el libro de incidentes fallan cerrado; los metadatos dicen lo que se probó.

1. `ChainLog`: una última línea cortada (corte a mitad de escritura, truncado) reventaba con JSONDecodeError y una entrada manipulada con KeyError/TypeError.
   Ahora todo es IntegrityError, `append` se niega a escribir sobre un registro roto y una escritura fallida no deja una línea rota.
2. `Ledger.update` dejaba BAJAR `repair_level` sin aprobador (de 3 «bloqueado hasta autorización» a 1 «automático»), poner estados o categorías que no existen.
3. `pyproject.toml` declaraba Python ≥ 3.11 y versión 0.1.0 mientras solo se prueba en 3.13/3.14 y el producto se llama 0.3.0-lab.
"""
import json
import re
from pathlib import Path

import pytest

from qce.core import chainlog
from qce.core.chainlog import ChainLog
from qce.core.errors import IntegrityError, QCEError
from qce.learning.ledger import Incident, Ledger

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def log(tmp_path):
    lg = ChainLog(tmp_path / "c.log")
    for i in range(3):
        lg.append({"n": i})
    return lg


# --- 1. ChainLog ---------------------------------------------------------------------------------------------------------------------------------------

def test_a_truncated_last_line_is_an_integrity_error_not_a_json_crash(log):
    data = log.path.read_bytes()
    log.path.write_bytes(data[:-20])                                          # corte a mitad de la última entrada
    for call in (log.entries, log.head, log.verify):
        with pytest.raises(IntegrityError, match="incompleta"):
            call()


def test_append_refuses_to_write_on_a_broken_log_instead_of_gluing_onto_it(log):
    size = log.path.stat().st_size
    log.path.write_bytes(log.path.read_bytes()[:-1])                          # solo falta el salto de línea final
    with pytest.raises(IntegrityError):
        log.append({"n": 99})
    assert log.path.stat().st_size == size - 1                                # no escribió nada


@pytest.mark.parametrize("bad", ["{no es json\n", "[1, 2]\n", '{"i": 0}\n', '{"i": "0", "ts": 1.0, "prev": "a", "body": "b", "hash": "c"}\n',
                                 '{"i": true, "ts": 1.0, "prev": "a", "body": "b", "hash": "c"}\n', '{"i": 0, "ts": "x", "prev": "a", "body": "b", "hash": "c"}\n',
                                 '{"i": 0, "ts": true, "prev": "a", "body": "b", "hash": "c"}\n', '{"i": 0, "ts": 1.0, "prev": 1, "body": "b", "hash": "c"}\n'])
def test_a_malformed_entry_is_an_integrity_error(tmp_path, bad):
    p = tmp_path / "c.log"
    p.write_text(bad)
    with pytest.raises(IntegrityError):
        ChainLog(p).verify()


def test_a_non_ascii_hash_is_a_broken_chain_not_a_type_error(log):
    lines = log.path.read_text().splitlines()
    e = json.loads(lines[1])
    e["hash"] = "é" * 64
    lines[1] = json.dumps(e)
    log.path.write_text("\n".join(lines) + "\n")
    with pytest.raises(IntegrityError, match="cadena rota"):
        log.verify()


def test_an_unreadable_log_is_an_integrity_error(tmp_path):
    p = tmp_path / "c.log"
    p.write_bytes(b"\xff\xfe\x00")                                           # no es UTF-8
    with pytest.raises(IntegrityError, match="no se puede leer"):
        ChainLog(p).entries()


def test_a_failed_write_does_not_leave_a_broken_line(log, monkeypatch):
    before = log.path.read_bytes()

    def boom(fd):
        raise OSError("disco lleno")
    monkeypatch.setattr(chainlog.os, "fsync", boom)
    with pytest.raises(OSError):
        log.append({"n": 99})
    monkeypatch.undo()
    assert log.path.read_bytes() == before                                    # la línea a medias se retiró
    assert log.verify() == 3
    log.append({"n": 4})
    assert log.verify() == 4


def test_a_good_log_with_blank_lines_still_verifies(log):
    log.path.write_text(log.path.read_text() + "\n\n")
    assert log.verify() == 3


def test_an_empty_or_missing_log_is_valid(tmp_path):
    lg = ChainLog(tmp_path / "x.log")
    assert lg.entries() == [] and lg.verify() == 0
    lg.path.write_text("")
    assert lg.verify() == 0


# --- 2. Ledger -----------------------------------------------------------------------------------------------------------------------------------------

def _open(led, iid="INC-1", **kw):
    return led.open(Incident(incident_id=iid, version="1", module="m", symptom="s", **kw))


@pytest.fixture
def led(tmp_path):
    return Ledger(tmp_path / "l.log")


def test_lowering_the_repair_level_needs_an_identified_approver(led):
    _open(led, repair_level=3)
    for kw in ({}, {"approver": ""}):
        with pytest.raises(QCEError, match="nivel de reparación"):
            led.update("INC-1", repair_level=1, **kw)
    assert led.get("INC-1")["repair_level"] == 3
    led.update("INC-1", repair_level=2, approver="humano")
    assert led.get("INC-1")["repair_level"] == 2


def test_raising_or_keeping_the_repair_level_needs_no_approver(led):
    _open(led, repair_level=2)
    led.update("INC-1", repair_level=2)
    led.update("INC-1", repair_level=3)
    assert led.get("INC-1")["repair_level"] == 3


@pytest.mark.parametrize("bad", [0, 4, -1, True, 2.0, "2", None])
def test_an_invalid_repair_level_is_refused(led, bad):
    with pytest.raises(QCEError, match="nivel de reparación"):
        _open(led, "INC-9", repair_level=bad)
    _open(led, repair_level=2)
    with pytest.raises(QCEError, match="nivel de reparación"):
        led.update("INC-1", repair_level=bad, approver="humano")


def test_raising_to_level_3_and_approving_in_one_step_still_needs_an_approver(led):
    _open(led, repair_level=2)
    with pytest.raises(QCEError, match="nivel 3"):
        led.update("INC-1", repair_level=3, approval="aprobado")
    led.update("INC-1", repair_level=3, approval="aprobado", approver="humano")
    assert led.get("INC-1")["approval"] == "aprobado"


def test_an_empty_approver_does_not_count_for_level_3_or_for_lowering_severity(led):
    _open(led, repair_level=3, severity="alta")
    with pytest.raises(QCEError, match="nivel 3"):
        led.update("INC-1", approval="aprobado", approver="")
    with pytest.raises(QCEError, match="severidad"):
        led.update("INC-1", severity="baja", approver="")


def test_statuses_and_root_causes_that_do_not_exist_are_refused(led):
    _open(led)
    with pytest.raises(QCEError, match="estado de incidente"):
        led.update("INC-1", status="cerrado")
    with pytest.raises(QCEError, match="categoría"):
        led.update("INC-1", root_cause_category="magia")
    led.update("INC-1", status="reproducido", root_cause_category="codigo")
    assert led.get("INC-1")["status"] == "reproducido"


# --- 3. Metadatos --------------------------------------------------------------------------------------------------------------------------------------

def _pyproject():
    return (ROOT / "pyproject.toml").read_text(encoding="utf-8")


def test_the_package_version_matches_the_product_version():
    from qce.cli import VERSION
    m = re.search(r'^version = "([^"]+)"', _pyproject(), re.M)
    assert m and m.group(1) == VERSION.split("-")[0], (m and m.group(1), VERSION)   # PEP 440 no admite el sufijo «-lab»: se compara el número


def test_requires_python_does_not_claim_versions_that_are_not_tested():
    declared = re.search(r'^requires-python = ">=(\d+)\.(\d+)"', _pyproject(), re.M)
    assert declared
    ci_pythons = {"3.13", "3.14"}                                             # CI Debian 13 (python3 = 3.13) y el equipo de desarrollo (3.14)
    assert f"{declared.group(1)}.{declared.group(2)}" in ci_pythons, "requires-python no puede ser menor que la versión más antigua probada"
    for doc in ("README.md", "review/REPRODUCCION.md"):
        if not (ROOT / doc).exists():                                         # el sandbox de mutación no lleva `review/` (activaría pruebas que exigen el repositorio entero)
            continue
        assert f"Python ≥ {declared.group(1)}.{declared.group(2)}" in (ROOT / doc).read_text(encoding="utf-8"), doc
