"""SLH-DSA-SHA2-128s (FIPS 205) por el puente ctypes de qce/pqc/slhdsa.py, con verificación cruzada contra la herramienta `openssl`."""
import os
import subprocess

import pytest

from qce.core.errors import AuthenticationFailure, MalformedMessage
from qce.pqc import slhdsa as S

try:
    S._crypto()
    HAVE = True
except Exception:  # noqa: BLE001
    HAVE = False
needs = pytest.mark.skipif(not HAVE, reason="sin OpenSSL ≥ 3.5 con SLH-DSA")
EXE = next((p for p in ("/opt/homebrew/bin/openssl", "/opt/homebrew/opt/openssl@3/bin/openssl", "/usr/local/bin/openssl") if os.path.exists(p)), None)
SPKI_PREFIX = bytes.fromhex("3030300b060960864801650304031403210" + "0")   # SubjectPublicKeyInfo de SLH-DSA-SHA2-128s (OID 2.16.840.1.101.3.4.3.20)


@pytest.fixture(scope="module")
def key():
    return S.SlhDsaPrivateKey.generate()


@needs
def test_sizes_roundtrip_and_a_valid_signature_verifies(key):
    assert (len(key.private_bytes()), len(key.public_bytes())) == (S.SK_LEN, S.PK_LEN)
    sig = key.sign(b"mensaje")
    assert len(sig) == S.SIG_LEN
    S.slhdsa_verify(key.public_bytes(), b"mensaje", sig)
    again = S.SlhDsaPrivateKey.from_bytes(key.private_bytes())
    assert again.public_bytes() == key.public_bytes()
    S.slhdsa_verify(key.public_bytes(), b"", key.sign(b""))                       # mensaje vacío


@needs
def test_tampering_with_message_signature_key_or_context_is_rejected(key):
    sig = key.sign(b"mensaje", context=b"ctx")
    S.slhdsa_verify(key.public_bytes(), b"mensaje", sig, b"ctx")
    for args in ((key.public_bytes(), b"mensajE", sig, b"ctx"), (key.public_bytes(), b"mensaje", sig, b"otro"), (key.public_bytes(), b"mensaje", sig, b""),
                 (S.SlhDsaPrivateKey.generate().public_bytes(), b"mensaje", sig, b"ctx")):
        with pytest.raises(AuthenticationFailure):
            S.slhdsa_verify(*args)
    for pos in (0, 17, S.SIG_LEN // 2, S.SIG_LEN - 1):
        bad = bytearray(sig)
        bad[pos] ^= 1
        with pytest.raises(AuthenticationFailure):
            S.slhdsa_verify(key.public_bytes(), b"mensaje", bytes(bad), b"ctx")


@needs
def test_lengths_and_context_limits_are_enforced(key):
    sig = key.sign(b"m")
    for bad in ((key.public_bytes()[:-1], b"m", sig), (key.public_bytes(), b"m", sig[:-1]), (key.public_bytes() + b"x", b"m", sig), (key.public_bytes(), b"m", sig + b"x")):
        with pytest.raises(MalformedMessage):
            S.slhdsa_verify(*bad)
    with pytest.raises(MalformedMessage):
        S.SlhDsaPrivateKey.from_bytes(key.private_bytes()[:-1])
    key.sign(b"m", context=bytes(S.CONTEXT_MAX))                                   # 255: límite inclusivo
    with pytest.raises(MalformedMessage):
        key.sign(b"m", context=bytes(S.CONTEXT_MAX + 1))
    with pytest.raises(MalformedMessage):
        S.slhdsa_verify(key.public_bytes(), b"m", sig, bytes(S.CONTEXT_MAX + 1))


@needs
def test_signatures_are_randomized_by_default_and_deterministic_on_request(key):
    assert key.sign(b"m") != key.sign(b"m")
    assert key.sign(b"m", deterministic=True) == key.sign(b"m", deterministic=True)
    S.slhdsa_verify(key.public_bytes(), b"m", key.sign(b"m", deterministic=True))


@needs
@pytest.mark.skipif(EXE is None, reason="sin la herramienta openssl")
def test_our_signature_verifies_with_the_openssl_command_line_tool(key, tmp_path):
    (tmp_path / "pk.der").write_bytes(SPKI_PREFIX + key.public_bytes())
    sig = key.sign(b"verificacion cruzada")
    (tmp_path / "m").write_bytes(b"verificacion cruzada")
    (tmp_path / "s").write_bytes(sig)
    cmd = [EXE, "pkeyutl", "-verify", "-pubin", "-keyform", "DER", "-inkey", str(tmp_path / "pk.der"), "-rawin", "-in", str(tmp_path / "m"), "-sigfile", str(tmp_path / "s")]
    assert subprocess.run(cmd, capture_output=True, text=True).returncode == 0
    (tmp_path / "m").write_bytes(b"otro mensaje")
    assert subprocess.run(cmd, capture_output=True, text=True).returncode != 0


@needs
@pytest.mark.skipif(EXE is None, reason="sin la herramienta openssl")
def test_a_signature_made_by_the_openssl_tool_verifies_with_our_code(tmp_path):
    run = lambda *a: subprocess.run([EXE, *a], capture_output=True, check=True)           # noqa: E731
    run("genpkey", "-algorithm", S.ALGORITHM, "-out", str(tmp_path / "sk.pem"))
    pub = subprocess.run([EXE, "pkey", "-in", str(tmp_path / "sk.pem"), "-pubout", "-outform", "DER"], capture_output=True, check=True).stdout
    assert pub.startswith(SPKI_PREFIX) and len(pub) == len(SPKI_PREFIX) + S.PK_LEN
    (tmp_path / "m").write_bytes(b"firmado por la herramienta")
    run("pkeyutl", "-sign", "-inkey", str(tmp_path / "sk.pem"), "-rawin", "-in", str(tmp_path / "m"), "-out", str(tmp_path / "s"))
    sig = (tmp_path / "s").read_bytes()
    S.slhdsa_verify(pub[len(SPKI_PREFIX):], b"firmado por la herramienta", sig)
    with pytest.raises(AuthenticationFailure):
        S.slhdsa_verify(pub[len(SPKI_PREFIX):], b"firmado por la herramientA", sig)


def test_primitive_fails_closed_without_a_usable_openssl(monkeypatch):
    from qce.core.errors import PolicyViolation
    from qce.core import openssl_ffi
    monkeypatch.setattr(S, "_cache", None)
    monkeypatch.setattr(openssl_ffi, "CANDIDATES", ("/no/existe/libssl.so.3",))
    with pytest.raises(PolicyViolation):
        S.SlhDsaPrivateKey.generate()


class Lying:
    """Envoltorio del libcrypto real que falsea la longitud devuelta por una función: la primitiva debe fallar cerrado."""

    def __init__(self, real, name, nth_arg):
        self._real, self._name, self._nth = real, name, nth_arg

    def __getattr__(self, attr):
        fn = getattr(self._real, attr)
        if attr != self._name:
            return fn

        def lie(*args):
            r = fn(*args)
            args[self._nth]._obj.value = max(args[self._nth]._obj.value - 1, 0)   # un byte menos de lo que dice el tamaño
            return r
        return lie


@needs
def test_a_library_that_reports_a_wrong_length_makes_the_primitive_fail_closed(monkeypatch, key):
    from qce.core.errors import PolicyViolation
    real = S._crypto()
    monkeypatch.setattr(S, "_crypto", lambda: Lying(real, "EVP_DigestSign", 2))
    with pytest.raises(PolicyViolation):
        key.sign(b"m")
    monkeypatch.setattr(S, "_crypto", lambda: Lying(real, "EVP_PKEY_get_octet_string_param", 4))
    with pytest.raises(PolicyViolation):
        S.SlhDsaPrivateKey.generate()


# ---- vectores oficiales NIST ACVP (usnistgov/ACVP-Server) --------------------------------------------------------------
import json
from pathlib import Path

ACVP = json.loads((Path(__file__).parent / "vectors" / "acvp_slhdsa_subset.json").read_text())


def test_acvp_subset_declares_its_provenance_and_scope():
    assert ACVP["source"].startswith("https://github.com/usnistgov/ACVP-Server") and ACVP["parameterSet"] == "SLH-DSA-SHA2-128s"
    assert len(ACVP["commit_upstream_al_recuperar"]) == 40 and all(len(h) == 64 for h in ACVP["sha256_original_files"].values())
    assert len(ACVP["keygen"]) == 10 and len(ACVP["sigver"]) == 14
    assert sum(1 for c in ACVP["sigver"] if c["testPassed"]) == 2 and sum(1 for c in ACVP["sigver"] if not c["testPassed"]) == 12   # hay casos negativos


@needs
@pytest.mark.parametrize("c", ACVP["keygen"], ids=lambda c: f"keygen-{c['tcId']}")
def test_keygen_from_the_official_seeds_matches_fips205(c):
    k = S.SlhDsaPrivateKey.from_seed(bytes.fromhex(c["skSeed"] + c["skPrf"] + c["pkSeed"]))
    assert k.private_bytes().hex().upper() == c["sk"].upper() and k.public_bytes().hex().upper() == c["pk"].upper()


@needs
@pytest.mark.parametrize("c", ACVP["sigver"], ids=lambda c: f"sigver-{c['tcId']}-{'valida' if c['testPassed'] else 'invalida'}")
def test_signature_verification_matches_fips205_for_valid_and_invalid_signatures(c):
    args = (bytes.fromhex(c["pk"]), bytes.fromhex(c["message"]), bytes.fromhex(c["signature"]), bytes.fromhex(c["context"]))
    if c["testPassed"]:
        S.slhdsa_verify(*args)
    else:
        with pytest.raises((AuthenticationFailure, MalformedMessage)):
            S.slhdsa_verify(*args)


@needs
def test_seeded_generation_is_deterministic_and_validates_its_input(key):
    seed = bytes(range(S.SEED_LEN))
    a, b = S.SlhDsaPrivateKey.from_seed(seed), S.SlhDsaPrivateKey.from_seed(seed)
    assert a.private_bytes() == b.private_bytes() != S.SlhDsaPrivateKey.from_seed(bytes(S.SEED_LEN)).private_bytes()
    S.slhdsa_verify(a.public_bytes(), b"m", a.sign(b"m"))
    for bad in (seed[:-1], seed + b"x", b"", None, "x" * S.SEED_LEN):
        with pytest.raises(MalformedMessage):
            S.SlhDsaPrivateKey.from_seed(bad)


class Counting:
    """Envoltorio del libcrypto que cuenta cuántos objetos se crean y se liberan: una fuga es un desequilibrio exacto, sin depender de la memoria residente."""

    def __init__(self, real):
        import collections
        self._r, self.n = real, collections.Counter()

    def __getattr__(self, name):
        fn = getattr(self._r, name)
        made = {"EVP_PKEY_fromdata": "pkey", "EVP_PKEY_keygen": "pkey", "EVP_MD_CTX_new": "mdctx", "EVP_PKEY_CTX_new_from_name": "pkeyctx"}
        freed = {"EVP_PKEY_free": "pkey", "EVP_MD_CTX_free": "mdctx", "EVP_PKEY_CTX_free": "pkeyctx"}
        if name in made:
            def w(*a):
                r = fn(*a)
                self.n[made[name] + "_new"] += (r == 1) if name in ("EVP_PKEY_fromdata", "EVP_PKEY_keygen") else bool(r)
                return r
            return w
        if name in freed:
            def w(p):
                self.n[freed[name] + "_free"] += bool(p)
                return fn(p)
            return w
        return fn


@needs
def test_every_openssl_object_the_primitive_creates_is_freed_on_every_path(monkeypatch, key):
    real = S._crypto()
    counting = Counting(real)
    monkeypatch.setattr(S, "_crypto", lambda: counting)
    k = S.SlhDsaPrivateKey.generate()
    S.SlhDsaPrivateKey.from_seed(bytes(S.SEED_LEN))
    sig = k.sign(b"m", b"ctx")
    sig2 = k.sign(b"m", deterministic=True)
    S.slhdsa_verify(k.public_bytes(), b"m", sig, b"ctx")                         # camino correcto
    for bad in ((k.public_bytes(), b"otro", sig, b"ctx"), (k.public_bytes(), b"m", sig, b"x"), (bytes(S.PK_LEN), b"m", sig2, b"")):
        with pytest.raises(AuthenticationFailure):
            S.slhdsa_verify(*bad)                                                    # caminos de rechazo
    for bad in ((k.public_bytes()[:-1], b"m", sig), (k.public_bytes(), b"m", sig[:-1])):
        with pytest.raises(MalformedMessage):
            S.slhdsa_verify(*bad)                                                    # rechazo antes de reservar nada
    with pytest.raises(MalformedMessage):
        k.sign(b"m", bytes(S.CONTEXT_MAX + 1))
    with pytest.raises(MalformedMessage):
        S.SlhDsaPrivateKey.from_seed(b"x")
    n = counting.n
    assert n["pkey_new"] == n["pkey_free"] > 0 and n["mdctx_new"] == n["mdctx_free"] > 0 and n["pkeyctx_new"] == n["pkeyctx_free"] > 0, dict(n)
