"""Aviso de OpenSSL por debajo de la versión que corrige un aviso publicado (`qce/core/openssl_advisories.py` y `qce tls-check`).

Las pruebas fijan los BORDES exactos de cada rama: una comparación `<` que pasase a `<=` marcaría como vulnerable justo la versión ya parcheada (falso positivo), y una `>` dejaría
sin avisar a la vulnerable (falso negativo, el peor caso).
"""
import subprocess
import sys
from datetime import date, timedelta
from pathlib import Path

import pytest

from qce import cli
from qce.core import openssl_advisories as adv
from qce.core import openssl_ffi

ROOT = Path(__file__).resolve().parent.parent


def num(major, minor, patch):
    """OPENSSL_VERSION_NUMBER (0xMNN00PP0) de una versión."""
    return (major << 28) | (minor << 20) | (patch << 4)


@pytest.mark.parametrize("number, expected", [
    (0x30600040, (3, 6, 4)), (0x30500090, (3, 5, 9)), (0x40000030, (4, 0, 3)),
    (0x300000d0, (3, 0, 13)), (0x305000a0, (3, 5, 10)),
])
def test_version_number_is_decoded_as_major_minor_patch(number, expected):
    assert adv.version_tuple(number) == expected


@pytest.mark.parametrize("version, status", [
    ((3, 5, 0), "below_floor"), ((3, 5, 8), "below_floor"), ((3, 5, 9), "ok"), ((3, 5, 10), "ok"), ((3, 5, 20), "ok"),
    ((3, 6, 0), "below_floor"), ((3, 6, 4), "below_floor"), ((3, 6, 5), "ok"), ((3, 6, 6), "ok"),
    ((4, 0, 0), "below_floor"), ((4, 0, 2), "below_floor"), ((4, 0, 3), "ok"), ((4, 0, 4), "ok"),
    ((3, 7, 0), "no_data"), ((3, 4, 8), "no_data"), ((3, 0, 13), "no_data"), ((4, 1, 0), "no_data"),
])
def test_each_branch_is_flagged_exactly_below_its_fixed_version(version, status):
    r = adv.assess(num(*version))
    assert r.status == status and r.version == ".".join(map(str, version))


def test_a_flagged_version_names_the_fix_the_advisory_the_date_and_the_source():
    d = adv.assess(0x30600040).detail
    assert "3.6.4" in d and "3.6.5" in d and "CVE-2026-84782" in d and "alta" in d
    assert str(adv.AS_OF) in d and adv.SOURCE in d
    assert "parcheado sin cambiar el número" in d                      # el límite honesto: retroportes de las distribuciones


def test_a_clean_or_unknown_version_does_not_claim_more_than_it_knows():
    ok = adv.assess(num(3, 6, 5)).detail
    assert "al día frente a los avisos de la tabla" in ok and "CVE" not in ok
    unknown = adv.assess(num(3, 7, 1)).detail
    assert "no tiene datos de la rama 3.7" in unknown and "al día" not in unknown     # sin datos NO es «seguro»


def test_the_table_only_covers_branches_the_project_accepts_and_has_real_floors():
    assert all(branch >= (3, 5) for branch in adv.BRANCH_FLOORS)        # QCE exige OpenSSL ≥ 3.5
    assert openssl_ffi.OPENSSL_MIN == num(3, 5, 0)
    assert all(floor > 0 and advisory.startswith("CVE-") and severity for floor, advisory, severity in adv.BRANCH_FLOORS.values())


@pytest.mark.parametrize("days, stale", [(0, False), (adv.STALE_AFTER_DAYS, False), (adv.STALE_AFTER_DAYS + 1, True)])
def test_table_age_is_measured_from_the_advisory_date(days, stale):
    today = adv.AS_OF + timedelta(days=days)
    assert adv.table_age_days(today) == days and (adv.table_age_days(today) > adv.STALE_AFTER_DAYS) == stale


def test_table_age_defaults_to_today():
    assert adv.table_age_days() == (date.today() - adv.AS_OF).days


# ---- la CLI --------------------------------------------------------------------------------------------------------------------
def report(monkeypatch, capsys, ssl_n, ffi_n, strict, why="", age=0):
    monkeypatch.setattr(cli, "_loaded_ffi_openssl_number", lambda: (ffi_n, why))
    monkeypatch.setattr(adv, "table_age_days", lambda today=None: age)
    rc = cli._report_openssl_advisories(ssl_n, strict)
    return rc, capsys.readouterr().out


@pytest.mark.parametrize("ssl_n, ffi_n, strict, rc", [
    (num(3, 6, 4), num(3, 6, 4), False, 0),     # avisar NO es fallar
    (num(3, 6, 4), num(3, 6, 4), True, 3),
    (num(3, 6, 5), num(3, 6, 4), True, 3),      # basta con que UNA de las dos esté por debajo
    (num(3, 6, 4), num(3, 6, 5), True, 3),
    (num(3, 6, 5), num(3, 5, 9), True, 0),
    (num(3, 7, 0), num(3, 7, 0), True, 0),      # sin datos: no se puede acusar
])
def test_only_strict_turns_a_warning_into_a_failure_exit_code(monkeypatch, capsys, ssl_n, ffi_n, strict, rc):
    got, out = report(monkeypatch, capsys, ssl_n, ffi_n, strict)
    assert got == rc and ("AVISO" in out) == (num(3, 6, 4) in (ssl_n, ffi_n))


def test_each_loaded_openssl_is_reported_under_its_own_label(monkeypatch, capsys):
    _, out = report(monkeypatch, capsys, num(3, 6, 5), num(3, 5, 8), False)
    lines = out.splitlines()
    assert "módulo ssl de Python: OpenSSL 3.6.5: al día" in lines[0]
    assert "puentes ctypes (libcrypto): AVISO: OpenSSL 3.5.8" in lines[1]


def test_when_the_ctypes_bridge_has_no_openssl_it_says_so_and_does_not_fail(monkeypatch, capsys):
    rc, out = report(monkeypatch, capsys, num(3, 6, 5), None, True, why="no hay una biblioteca OpenSSL ≥ 3.5 utilizable")
    assert rc == 0 and "puentes ctypes (libcrypto): no disponible (no hay una biblioteca" in out


def test_a_stale_table_says_so(monkeypatch, capsys):
    _, out = report(monkeypatch, capsys, num(3, 6, 5), num(3, 6, 5), False, age=adv.STALE_AFTER_DAYS + 40)
    assert f"{adv.STALE_AFTER_DAYS + 40} días" in out and "qce/core/openssl_advisories.py" in out
    _, fresh = report(monkeypatch, capsys, num(3, 6, 5), num(3, 6, 5), False, age=10)
    assert "días" not in fresh


def test_loaded_number_comes_from_the_real_libcrypto_or_reports_why_not(monkeypatch):
    number, why = cli._loaded_ffi_openssl_number()
    assert (number is not None and number >= openssl_ffi.OPENSSL_MIN and not why) or (number is None and why)

    def none_available(*a, **k):
        raise openssl_ffi.OpenSslUnavailable("sin OpenSSL")
    monkeypatch.setattr(openssl_ffi, "load", none_available)
    assert cli._loaded_ffi_openssl_number() == (None, "sin OpenSSL")


def test_real_tls_check_strict_exit_code_agrees_with_its_own_output():
    """Independiente del equipo: si el comando imprime un AVISO, `--strict` sale con 3; si no, con 0."""
    r = subprocess.run([sys.executable, "-m", "qce", "tls-check", "--strict"], cwd=ROOT, capture_output=True, text=True, timeout=120)
    assert "atestación OK" in r.stdout, r.stdout + r.stderr
    assert r.returncode == (3 if "AVISO" in r.stdout else 0)
    plain = subprocess.run([sys.executable, "-m", "qce", "tls-check"], cwd=ROOT, capture_output=True, text=True, timeout=120)
    assert plain.returncode == 0                                     # sin --strict nunca falla por un aviso
