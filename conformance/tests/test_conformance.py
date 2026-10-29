"""Pruebas del conjunto de conformidad: `python -m pytest conformance/tests -o addopts= -q` (fuera de `tests/`: no cambian el release_id).
Incluyen «canarios»: comprueban que los ejecutores SÍ fallan cuando algo está mal (un verde sin esa prueba podría estar vacío)."""
import copy
import shutil
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
import differential  # noqa: E402
import run_wycheproof as rw  # noqa: E402

have_vectors = all((HERE / "vectors" / n).exists() for n in rw.MANIFEST["files"])
needs_vectors = pytest.mark.skipif(not have_vectors, reason="faltan vectores: python conformance/fetch_vectors.py")
needs_cli = pytest.mark.skipif(not shutil.which("openssl"), reason="no hay openssl en el PATH")


@needs_vectors
def test_all_wycheproof_vectors_pass_and_enough_were_executed():
    rep = rw.run_all()
    assert rep["ok"], rep
    assert sum(v["ejecutadas"] for v in rep["archivos"].values()) >= 1500


@needs_vectors
def test_canary_a_wrong_expected_secret_is_reported():
    def tamper(name, data):
        if name == "mlkem_768_test":
            d = copy.deepcopy(data)
            t = next(t for g in d["testGroups"] for t in g["tests"] if t["result"] == "valid")
            t["K"] = "00" * 32
            return d
        return data
    assert not rw.run_all(tamper)["ok"]


@needs_vectors
def test_canary_an_invalid_signature_declared_valid_is_reported():
    def tamper(name, data):
        if name == "mldsa_65_verify_test":
            d = copy.deepcopy(data)
            next(t for g in d["testGroups"] for t in g["tests"] if t["result"] == "invalid")["result"] = "valid"
            return d
        return data
    assert not rw.run_all(tamper)["ok"]


@needs_vectors
def test_canary_an_accepted_malformed_encapsulation_key_would_be_reported():
    def tamper(name, data):
        if name == "mlkem_768_encaps_test":
            d = copy.deepcopy(data)
            tests = [t for g in d["testGroups"] for t in g["tests"]]
            good = next(t for t in tests if t["result"] == "valid")
            bad = next(t for t in tests if t["result"] == "invalid")
            bad["ek"] = good["ek"]  # ahora una clave VÁLIDA figura como «debe rechazarse»: el ejecutor tiene que notarlo
            return d
        return data
    assert not rw.run_all(tamper)["ok"]


@needs_vectors
def test_canary_too_few_executed_tests_is_not_a_pass():
    def tamper(name, data):
        d = copy.deepcopy(data)
        for g in d["testGroups"]:
            g["tests"] = g["tests"][:1]
        return d
    assert not rw.run_all(tamper)["ok"]


@needs_vectors
def test_manifest_hash_mismatch_aborts(tmp_path, monkeypatch):
    monkeypatch.setitem(rw.MANIFEST["files"], "mlkem_768_test.json", "0" * 64)
    with pytest.raises(SystemExit):
        rw.load("mlkem_768_test")


@needs_cli
def test_differential_finds_no_differences_between_the_two_openssl_builds():
    rep = differential.run(3)
    assert rep["ok"], rep


@needs_cli
def test_canary_differential_reports_a_forced_difference(monkeypatch):
    monkeypatch.setattr(differential, "pub_der", lambda pub: b"x")
    assert not differential.run(1)["ok"]
