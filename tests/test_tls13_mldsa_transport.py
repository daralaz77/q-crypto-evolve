"""EXPERIMENTAL (rama exp/mldsa-transport): autenticación ML-DSA en el transporte TLS 1.3 real de qce, no solo con `openssl s_client`."""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCEN = ROOT / "tests" / "mldsa_scenarios.py"
ALGS = ("ml-dsa-65", "ml-dsa-87")
OIDS = {"ecdsa-p256": "1.2.840.10045.4.3.2", "ml-dsa-65": "2.16.840.1.101.3.4.3.18", "ml-dsa-87": "2.16.840.1.101.3.4.3.19"}


def scenario(name, alg, timeout=90):
    env = {k: v for k, v in os.environ.items() if k != "OPENSSL_CONF"}
    env["PYTHONPATH"] = str(ROOT)
    r = subprocess.run([sys.executable, str(SCEN), name, alg], capture_output=True, text=True, timeout=timeout, env=env, cwd=ROOT)
    assert r.returncode == 0, r.stderr[-800:]
    return json.loads(r.stdout.strip().splitlines()[-1])


@pytest.mark.parametrize("alg", ("ecdsa-p256",) + ALGS)
def test_handshake_with_each_signature_algorithm_over_the_real_transport(alg):
    out = scenario("handshake", alg)
    assert out["ok"] and out["version"] == "TLSv1.3" and out["signature_oid"] == OIDS[alg]


def test_mldsa_certificates_are_much_larger_than_ecdsa_ones():
    sizes = {a: scenario("handshake", a)["der_bytes"] for a in ("ecdsa-p256",) + ALGS}
    assert sizes["ml-dsa-65"] > 10 * sizes["ecdsa-p256"] and sizes["ml-dsa-87"] > sizes["ml-dsa-65"]


@pytest.mark.parametrize("alg", ALGS)
def test_canary_a_client_that_trusts_another_mldsa_ca_must_refuse(alg):
    assert scenario("wrong_ca", alg)["ok"] is False


@pytest.mark.parametrize("alg", ALGS)
def test_canary_a_wrong_server_name_must_be_refused(alg):
    assert scenario("wrong_name", alg)["ok"] is False


@pytest.mark.parametrize("alg", ALGS)
def test_mutual_authentication_with_mldsa_client_certificates(alg):
    out = scenario("mutual", alg)
    assert out["with_client_cert"]["ok"] is True
    assert out["without_client_cert"]["ok"] is False  # el servidor exige certificado de cliente


@pytest.mark.parametrize("alg", ALGS)
def test_revocation_by_an_mldsa_signed_crl(alg):
    out = scenario("crl", alg)
    assert out["revoked"]["ok"] is False and out["not_revoked"]["ok"] is True


@pytest.mark.parametrize("alg", ALGS)
def test_server_key_held_by_the_keystore_custody_can_be_mldsa(alg):
    out = scenario("custody", alg)
    assert out["ok"] is True and out["kid_has_cert"]
    assert out["files_with_private_key_besides_the_lab_leaf"] == []  # la clave custodiada nunca queda en claro en disco
