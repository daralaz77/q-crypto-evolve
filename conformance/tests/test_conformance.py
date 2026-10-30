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

have_vectors = all((rw.VECTORS_DIR / n).exists() for n in rw.MANIFEST["files"])
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
def test_canary_a_reference_signature_that_does_not_verify_is_reported():
    def tamper(name, data):
        if name == "mldsa_65_sign_seed_test":
            d = copy.deepcopy(data)
            t = next(t for g in d["testGroups"] for t in g["tests"] if t["result"] == "valid")
            t["sig"] = "00" + t["sig"][2:]  # firma de referencia corrompida: tiene que dejar de verificar
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


# ---- segunda implementación independiente (mlkem-native), solo si está compilada ----
import os  # noqa: E402

import independent  # noqa: E402

LIB = os.environ.get("QCE_MLKEM_NATIVE_LIB")
needs_native = pytest.mark.skipif(not (LIB and Path(LIB).exists() and have_vectors), reason="falta QCE_MLKEM_NATIVE_LIB (python conformance/build_mlkem_native.py) o los vectores")


@needs_native
def test_native_passes_the_wycheproof_vectors_that_cryptography_cannot_run():
    rep = independent.wycheproof_native(independent.Native(LIB))
    assert rep["ok"], rep
    assert rep["archivos"]["mlkem_768_semi_expanded_decaps_test"]["ejecutadas"] >= 5  # clave expandida: lo que cryptography no importa


@needs_native
def test_native_and_cryptography_agree_on_random_seeds():
    rep = independent.differential_native(independent.Native(LIB), 10)
    assert rep["ok"], rep


@needs_native
def test_canary_native_runner_fails_when_an_expected_secret_is_altered():
    def tamper(name, data):
        if name == "mlkem_768_semi_expanded_decaps_test":
            d = copy.deepcopy(data)
            next(t for g in d["testGroups"] for t in g["tests"] if t["result"] == "valid")["K"] = "00" * 32
            return d
        return data
    assert not independent.wycheproof_native(independent.Native(LIB), tamper)["ok"]


def test_build_script_pins_a_commit_and_a_sha256():
    import build_mlkem_native as b
    assert len(b.COMMIT) == 40 and len(b.SHA256) == 64 and b.COMMIT in b.URL


# ---- B1: autenticación ML-DSA en TLS 1.3 con las herramientas actuales ----
import tempfile  # noqa: E402

import tls_mldsa_probe as probe  # noqa: E402


@needs_cli
def test_tls13_handshake_with_mldsa_certificates_works_in_openssl_and_python_ssl():
    for alg in ("ML-DSA-65", "ML-DSA-87"):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            probe.make_pki(d, alg)
            cli, py = probe.cli_handshake(d), probe.python_ssl_handshake(d)
            assert cli["ok"] and cli["firma_de_par"] == alg.lower().replace("-", "")
            assert py["ok"] and py["version"] == "TLSv1.3"


@needs_cli
def test_canary_a_client_trusting_a_different_ca_must_fail_the_mldsa_handshake():
    with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
        da, db = Path(a), Path(b)
        probe.make_pki(da, "ML-DSA-65")
        probe.make_pki(db, "ML-DSA-65")
        (da / "ca.pem").write_bytes((db / "ca.pem").read_bytes())  # el cliente confía en OTRA CA
        assert not probe.cli_handshake(da)["ok"]
        assert not probe.python_ssl_handshake(da)["ok"]


# ---- ML-DSA: segunda implementación independiente (mldsa-native), solo si está compilada ----
import independent_dsa  # noqa: E402

DSA_LIB = os.environ.get("QCE_MLDSA_NATIVE_LIB")
needs_dsa = pytest.mark.skipif(not (DSA_LIB and Path(DSA_LIB).exists() and have_vectors), reason="falta QCE_MLDSA_NATIVE_LIB (python conformance/build_mldsa_native.py) o los vectores")


@needs_dsa
def test_mldsa_native_passes_wycheproof_and_reproduces_deterministic_signatures_byte_for_byte():
    rep = independent_dsa.wycheproof_native(independent_dsa.NativeDsa(DSA_LIB))
    assert rep["ok"], rep
    assert rep["archivos"]["mldsa_65_sign_seed_test"]["firma_determinista_identica_al_vector"] >= 90


@needs_dsa
def test_mldsa_native_and_cryptography_agree_on_random_seeds():
    assert independent_dsa.differential_native(independent_dsa.NativeDsa(DSA_LIB), 8)["ok"]


@needs_dsa
def test_canary_a_deterministic_reference_signature_that_does_not_reproduce_is_reported():
    def tamper(name, data):
        if name == "mldsa_65_sign_seed_test":
            d = copy.deepcopy(data)
            t = next(t for g in d["testGroups"] for t in g["tests"] if t["result"] == "valid" and "msg" in t and "Randomized" not in t.get("flags", []))
            t["sig"] = t["sig"][:-2] + ("00" if t["sig"][-2:] != "00" else "01")
            return d
        return data
    assert not independent_dsa.wycheproof_native(independent_dsa.NativeDsa(DSA_LIB), tamper)["ok"]


def test_mldsa_build_script_pins_a_commit_and_a_sha256():
    import build_mldsa_native as b
    assert len(b.COMMIT) == 40 and len(b.SHA256) == 64 and b.COMMIT in b.URL
