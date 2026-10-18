"""Vectores oficiales NIST ACVP (usnistgov/ACVP-Server). Subconjunto extraído en tests/vectors/.

Verifican la biblioteca subyacente (cryptography/OpenSSL) contra FIPS 203/204; NO prueban la
composición híbrida de este proyecto (para eso están el resto de pruebas).
"""
import json
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import mldsa, mlkem

V = json.loads((Path(__file__).parent / "vectors" / "acvp_subset.json").read_text())


@pytest.mark.parametrize("c", V["mlkem768_keygen"]["cases"])
def test_mlkem768_keygen_matches_fips203(c):
    seed = bytes.fromhex(c["d"]) + bytes.fromhex(c["z"])  # semilla FIPS 203 = d || z
    k = mlkem.MLKEM768PrivateKey.from_seed_bytes(seed)
    assert k.public_key().public_bytes_raw().hex().upper() == c["ek"].upper()


@pytest.mark.parametrize("c", V["mldsa65_keygen"]["cases"])
def test_mldsa65_keygen_matches_fips204(c):
    k = mldsa.MLDSA65PrivateKey.from_seed_bytes(bytes.fromhex(c["seed"]))
    assert k.public_key().public_bytes_raw().hex().upper() == c["pk"].upper()


@pytest.mark.parametrize("c", V["mldsa65_sigver"]["cases"])
def test_mldsa65_sigver_matches_fips204(c):
    expect = c["expected"] in (True, "True", "true")
    try:
        pk = mldsa.MLDSA65PublicKey.from_public_bytes(bytes.fromhex(c["pk"]))
        pk.verify(bytes.fromhex(c["signature"]), bytes.fromhex(c["message"]), bytes.fromhex(c["context"]) or None)
        ok = True
    except (InvalidSignature, ValueError):
        ok = False
    assert ok == expect


def test_vectors_are_nonempty_and_include_negative_cases():
    assert len(V["mlkem768_keygen"]["cases"]) >= 10 and len(V["mldsa65_keygen"]["cases"]) >= 10
    sv = V["mldsa65_sigver"]["cases"]
    assert any(c["expected"] in (False, "False") for c in sv) and any(c["expected"] in (True, "True") for c in sv)
