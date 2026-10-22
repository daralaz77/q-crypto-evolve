"""Niveles de parámetros poscuánticos: STANDARD (ML-KEM-768 / ML-DSA-65, el valor por defecto) y HIGH (ML-KEM-1024 / ML-DSA-87, los que pide CNSA 2.0).

Qué se comprueba: que HIGH funciona de extremo a extremo (KEM, firma, handshake QCE1 con identidad y sesión), que el nivel NUNCA se deduce de lo que llega por la red,
que mezclar niveles falla cerrado, que la política por defecto NO admite HIGH (hay que activarlo a propósito) y que los vectores oficiales de NIST para 1024/87 los cumple la biblioteca.
Usar estos parámetros no hace al sistema conforme con CNSA 2.0 (ver docs/FIPS_140_3.md).
"""
import json
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import mldsa, mlkem

from qce.core.errors import AuthenticationFailure, MalformedMessage, PolicyViolation
from qce.core.policy import SUITES, Policy
from qce.pqc import hybrid
from qce.pqc.hybrid import HIGH, LEVELS, STANDARD, HybridKemPrivateKey, HybridSigPrivateKey, hybrid_encapsulate, hybrid_verify
from qce.protocols.session import ClientHandshake, ServerHandshake

HIGH_SUITE = "QCE1-XMLKEM1024-AESGCM"
V = json.loads((Path(__file__).parent / "vectors" / "acvp_subset_high.json").read_text())


def handshake(client_policy, server_policy, client_pinned, server_identity):
    c, s = ClientHandshake(client_pinned.public_bytes, client_policy), ServerHandshake(server_identity, server_policy)
    m2 = s.on_client_hello(c.start())
    m4, srv_sess = s.on_client_finish(c.on_server_hello(m2))
    return c.on_server_finish(m4), srv_sess, c


# ---- tamaños y registro -------------------------------------------------------------------------------------------
@pytest.mark.parametrize("level", [STANDARD, HIGH], ids=lambda lv: lv.name)
def test_the_size_table_matches_what_the_library_really_produces(level):
    k, sk = HybridKemPrivateKey.generate(level), HybridSigPrivateKey.generate(level)
    ss, ct = hybrid_encapsulate(k.public_bytes, level)
    assert (len(k.public_bytes), len(ct)) == (level.kem_pk_len, level.kem_ct_len)
    assert (len(sk.public_bytes), len(sk.sign(b"m", b"c"))) == (level.sig_pk_len, level.sig_len)
    assert len(k.seed()) == 32 + level.mlkem_seed and len(sk.seed()) == 32 + level.mldsa_seed


def test_the_two_levels_have_different_parameters_and_domain_labels():
    assert (STANDARD.mlkem_pk, HIGH.mlkem_pk, STANDARD.mldsa_pk, HIGH.mldsa_pk) == (1184, 1568, 1952, 2592)
    assert STANDARD.label != HIGH.label and b"ML-KEM-768" in STANDARD.label and b"ML-KEM-1024" in HIGH.label
    assert set(LEVELS) == {"standard", "high"} and hybrid.KEM_PK_LEN == STANDARD.kem_pk_len   # las constantes antiguas siguen siendo las del nivel por defecto


# ---- KEM y firma, por nivel ---------------------------------------------------------------------------------------
@pytest.mark.parametrize("level", [STANDARD, HIGH], ids=lambda lv: lv.name)
def test_kem_round_trip_and_seed_reconstruction(level):
    k = HybridKemPrivateKey.generate(level)
    ss, ct = hybrid_encapsulate(k.public_bytes, level)
    assert k.decapsulate(ct) == ss
    k2 = HybridKemPrivateKey.from_seed(k.seed(), level)
    assert k2.public_bytes == k.public_bytes and k2.decapsulate(ct) == ss
    other = HybridKemPrivateKey.generate(level)
    assert other.decapsulate(ct) != ss                                        # otra clave: rechazo implícito, secreto distinto


def test_the_same_inputs_never_give_the_same_secret_at_the_two_levels():
    """Separación de dominios: la etiqueta incluye el nivel."""
    a = hybrid._combine(b"m" * 32, b"x" * 32, b"ct", b"pk", STANDARD)
    b = hybrid._combine(b"m" * 32, b"x" * 32, b"ct", b"pk", HIGH)
    assert a != b


@pytest.mark.parametrize("level", [STANDARD, HIGH], ids=lambda lv: lv.name)
def test_signature_round_trip_tamper_and_context_separation(level):
    sk = HybridSigPrivateKey.generate(level)
    sig = sk.sign(b"mensaje", b"ctx")
    hybrid_verify(sk.public_bytes, b"mensaje", sig, b"ctx", level)
    for args in ((b"otro", sig, b"ctx"), (b"mensaje", sig, b"otro-ctx"), (b"mensaje", sig[:-1] + bytes([sig[-1] ^ 1]), b"ctx"), (b"mensaje", bytes([sig[0] ^ 1]) + sig[1:], b"ctx")):
        with pytest.raises(AuthenticationFailure):
            hybrid_verify(sk.public_bytes, args[0], args[1], args[2], level)
    assert HybridSigPrivateKey.from_seed(sk.seed(), level).public_bytes == sk.public_bytes


def test_a_key_or_signature_of_the_other_level_is_refused_by_length_and_never_guessed():
    ks, kh = HybridKemPrivateKey.generate(STANDARD), HybridKemPrivateKey.generate(HIGH)
    with pytest.raises(MalformedMessage):
        hybrid_encapsulate(kh.public_bytes, STANDARD)
    with pytest.raises(MalformedMessage):
        hybrid_encapsulate(ks.public_bytes, HIGH)
    _, ct_h = hybrid_encapsulate(kh.public_bytes, HIGH)
    with pytest.raises(MalformedMessage):
        ks.decapsulate(ct_h)
    ss_, sh = HybridSigPrivateKey.generate(STANDARD), HybridSigPrivateKey.generate(HIGH)
    sig_h = sh.sign(b"m", b"c")
    with pytest.raises(AuthenticationFailure):
        hybrid_verify(sh.public_bytes, b"m", sig_h, b"c", STANDARD)
    with pytest.raises(AuthenticationFailure):
        hybrid_verify(ss_.public_bytes, b"m", ss_.sign(b"m", b"c"), b"c", HIGH)
    # las semillas miden lo mismo en los dos niveles: no hay error, pero el nivel lo decide quien llama y la clave resultante es OTRA (otra longitud)
    assert len(HybridKemPrivateKey.from_seed(ks.seed(), HIGH).public_bytes) == HIGH.kem_pk_len != len(ks.public_bytes)
    assert len(HybridSigPrivateKey.from_seed(sh.seed(), STANDARD).public_bytes) == STANDARD.sig_pk_len != len(sh.public_bytes)
    with pytest.raises(MalformedMessage):                                      # lo que sí falla: una semilla de longitud inventada
        HybridKemPrivateKey.from_seed(ks.seed()[:-1], HIGH)


# ---- suites, política y handshake QCE1 ------------------------------------------------------------------------------
def test_the_high_suite_is_registered_but_not_in_the_default_policy():
    assert SUITES[HIGH_SUITE].level == "high" and SUITES["QCE1-XMLKEM768-AESGCM"].level == "standard"
    assert HIGH_SUITE not in Policy().allowed_suites                           # hay que activarlo a propósito
    with pytest.raises(PolicyViolation):
        Policy().check_suite(HIGH_SUITE)
    Policy(allowed_suites=(HIGH_SUITE,)).check_suite(HIGH_SUITE)


def test_a_full_qce1_handshake_at_the_high_level_exchanges_records():
    ident = HybridSigPrivateKey.generate(HIGH)
    pol = Policy(allowed_suites=(HIGH_SUITE,))
    cs, ss, c = handshake(pol, pol, ident, ident)
    assert c.suite.suite_id == HIGH_SUITE and c.suite.level == "high"
    assert ss.open(cs.seal(b"hola nivel alto", b"aad"), b"aad") == b"hola nivel alto"
    assert cs.open(ss.seal(b"respuesta", b"aad"), b"aad") == b"respuesta"


def test_a_default_policy_server_refuses_a_client_that_only_offers_the_high_suite():
    ident = HybridSigPrivateKey.generate(HIGH)
    c = ClientHandshake(ident.public_bytes, Policy(allowed_suites=(HIGH_SUITE,)))
    with pytest.raises(PolicyViolation):
        ServerHandshake(ident, Policy()).on_client_hello(c.start())           # sin suite común: no hay bajada ni subida silenciosa


def test_a_server_whose_identity_is_not_of_the_suite_level_aborts_instead_of_signing_with_another_level():
    std_ident = HybridSigPrivateKey.generate(STANDARD)
    pol = Policy(allowed_suites=(HIGH_SUITE,))
    c = ClientHandshake(std_ident.public_bytes, pol)
    with pytest.raises(PolicyViolation):
        ServerHandshake(std_ident, pol).on_client_hello(c.start())


def test_a_client_that_pinned_an_identity_of_the_wrong_level_never_completes():
    high_ident, std_pinned = HybridSigPrivateKey.generate(HIGH), HybridSigPrivateKey.generate(STANDARD)
    pol = Policy(allowed_suites=(HIGH_SUITE,))
    c, s = ClientHandshake(std_pinned.public_bytes, pol), ServerHandshake(high_ident, pol)
    m2 = s.on_client_hello(c.start())
    with pytest.raises(AuthenticationFailure):
        c.on_server_hello(m2)


def test_the_default_suites_still_use_the_standard_level_unchanged():
    ident = HybridSigPrivateKey.generate()
    c = ClientHandshake(ident.public_bytes, Policy())
    s = ServerHandshake(ident, Policy())
    m2 = s.on_client_hello(c.start())
    assert c.on_server_hello.__self__ is c and s.suite.level == "standard" and len(ident.public_bytes) == STANDARD.sig_pk_len
    m4, _ = s.on_client_finish(c.on_server_hello(m2))
    c.on_server_finish(m4)


# ---- vectores oficiales NIST (ACVP) para 1024 / 87 ------------------------------------------------------------------
@pytest.mark.parametrize("c", V["mlkem1024_keygen"]["cases"], ids=lambda c: f"tc{c['tcId']}")
def test_mlkem1024_keygen_matches_fips203(c):
    k = mlkem.MLKEM1024PrivateKey.from_seed_bytes(bytes.fromhex(c["d"]) + bytes.fromhex(c["z"]))
    assert k.public_key().public_bytes_raw().hex().upper() == c["ek"].upper()


@pytest.mark.parametrize("c", V["mldsa87_keygen"]["cases"], ids=lambda c: f"tc{c['tcId']}")
def test_mldsa87_keygen_matches_fips204(c):
    k = mldsa.MLDSA87PrivateKey.from_seed_bytes(bytes.fromhex(c["seed"]))
    assert k.public_key().public_bytes_raw().hex().upper() == c["pk"].upper()


@pytest.mark.parametrize("c", V["mldsa87_sigver"]["cases"], ids=lambda c: f"tc{c['tcId']}")
def test_mldsa87_sigver_matches_fips204(c):
    expect = c["expected"] in (True, "True", "true")
    try:
        mldsa.MLDSA87PublicKey.from_public_bytes(bytes.fromhex(c["pk"])).verify(bytes.fromhex(c["signature"]), bytes.fromhex(c["message"]), bytes.fromhex(c["context"]) or None)
        ok = True
    except (InvalidSignature, ValueError):
        ok = False
    assert ok == expect


def test_the_high_vectors_are_nonempty_have_negative_cases_and_carry_their_provenance():
    assert len(V["mlkem1024_keygen"]["cases"]) >= 10 and len(V["mldsa87_keygen"]["cases"]) >= 10
    sv = V["mldsa87_sigver"]["cases"]
    assert any(c["expected"] in (False, "False") for c in sv) and any(c["expected"] in (True, "True") for c in sv)
    for k in ("mlkem1024_keygen", "mldsa87_keygen", "mldsa87_sigver"):
        assert len(V[k]["prompt_sha256"]) == 64 and len(V[k]["expected_sha256"]) == 64 and V[k]["source"].startswith("gen-val/json-files/")
    assert "commit_upstream_al_recuperar" in V["_procedencia"] and V["_procedencia"]["repositorio"].startswith("https://github.com/usnistgov/ACVP-Server")
