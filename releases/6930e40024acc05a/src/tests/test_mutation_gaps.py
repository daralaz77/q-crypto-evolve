"""Pruebas añadidas porque la prueba de mutación (qce.evolve.mutation) demostró lagunas reales."""
import struct

import pytest

from qce.core import encoding
from qce.core.chainlog import ChainLog
from qce.core.errors import IntegrityError, KeyStateError, MalformedMessage, PolicyViolation
from qce.core.policy import SUITES, Policy, Suite
from qce.key_management import vault
from qce.key_management.keystore import KeyStore, Purpose
from qce.pqc import hybrid


def test_combiner_depends_on_every_input():
    base = hybrid._combine(b"m" * 32, b"x" * 32, b"ct", b"pk")
    assert hybrid._combine(b"M" * 32, b"x" * 32, b"ct", b"pk") != base  # componente ML-KEM
    assert hybrid._combine(b"m" * 32, b"X" * 32, b"ct", b"pk") != base  # componente X25519
    assert hybrid._combine(b"m" * 32, b"x" * 32, b"CT", b"pk") != base  # enlace al texto cifrado
    assert hybrid._combine(b"m" * 32, b"x" * 32, b"ct", b"PK") != base  # enlace a la clave pública


def test_policy_allowlist_is_enforced_not_just_registry_status():
    p = Policy(allowed_suites=("QCE1-XMLKEM768-CHACHA",))
    p.check_suite("QCE1-XMLKEM768-CHACHA")
    with pytest.raises(PolicyViolation):
        p.check_suite("QCE1-XMLKEM768-AESGCM")  # válida en el registro, pero no autorizada aquí


def test_policy_refuses_allowed_but_non_hybrid_suite(monkeypatch):
    monkeypatch.setitem(SUITES, "QCE9-PLAIN-MLKEM", Suite("QCE9-PLAIN-MLKEM", "ML-KEM-768", "ML-DSA-65", "AES-256-GCM", "allowed"))
    with pytest.raises(PolicyViolation):
        Policy(allowed_suites=("QCE9-PLAIN-MLKEM",))  # PQC sin componente clásico: no se admite


def test_encoding_rejects_trailing_bytes_and_oversized_field():
    good = encoding.pack(1, [b"abc"])
    with pytest.raises(MalformedMessage):
        encoding.unpack(good + b"\x00", 1, 1)
    big = encoding.MAX_FIELD + 1
    msg = struct.pack(">BB", 1, 1) + struct.pack(">I", big) + b"\x00" * big
    with pytest.raises(MalformedMessage):
        encoding.unpack(msg, 1, 1)


def test_key_expires_exactly_at_not_after():
    t = [1000.0]
    ks = KeyStore(clock=lambda: t[0])
    kid = ks.create(Purpose.ENCRYPT, 10)
    ks.activate(kid)
    t[0] = 1009.999
    ks.protect(kid, b"x")
    t[0] = 1010.0  # límite inclusivo
    with pytest.raises(KeyStateError):
        ks.protect(kid, b"x")


def test_vault_refuses_weak_kdf_parameters(tmp_path):
    ks = KeyStore()
    ks.create(Purpose.ENCRYPT, 10)
    weak = tmp_path / "weak.bin"
    vault.save(ks, weak, "frase-larga", n=2**10)  # el escritor sí puede crearlo…
    with pytest.raises(IntegrityError):
        vault.load(weak, "frase-larga")  # …pero el lector nunca acepta KDF degradado
