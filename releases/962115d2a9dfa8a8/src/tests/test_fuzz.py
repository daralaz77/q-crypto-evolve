"""Fuzzing basado en propiedades: ninguna entrada hostil puede causar otra cosa que un QCEError."""
import pytest
from hypothesis import HealthCheck, given, settings, strategies as st

from qce.core.encoding import pack, unpack
from qce.core.errors import QCEError
from qce.pqc.hybrid import HybridKemPrivateKey, HybridSigPrivateKey, hybrid_verify
from qce.protocols.session import ClientHandshake, ServerHandshake

SET = settings(max_examples=150, deadline=None, suppress_health_check=[HealthCheck.too_slow])
_ident = HybridSigPrivateKey.generate()


@SET
@given(st.lists(st.binary(max_size=300), max_size=8), st.integers(0, 255))
def test_pack_unpack_roundtrip(fields, tag):
    assert unpack(pack(tag, fields), tag, len(fields)) == fields


@SET
@given(st.binary(max_size=600))
def test_unpack_only_raises_qce_errors(data):
    for tag in (1, 2, 3):
        for n in (1, 2, 4):
            try:
                unpack(data, tag, n)
            except QCEError:
                pass


@SET
@given(st.binary(max_size=3000))
def test_server_hello_parser_is_total(data):
    try:
        ServerHandshake(_ident).on_client_hello(data)
    except QCEError:
        pass


@SET
@given(st.binary(max_size=5000))
def test_client_parsers_are_total(data):
    c = ClientHandshake(_ident.public_bytes)
    c.start()
    try:
        c.on_server_hello(data)
    except QCEError:
        pass


@SET
@given(st.integers(0, 1119), st.integers(1, 255))
def test_any_single_byte_flip_in_kem_ct_changes_secret(pos, xor):
    from qce.pqc.hybrid import hybrid_encapsulate
    k = _KEM
    ss, ct = hybrid_encapsulate(k.public_bytes)
    bad = bytearray(ct)
    bad[pos] ^= xor
    assert k.decapsulate(bytes(bad)) != ss


_KEM = HybridKemPrivateKey.generate()


@SET
@given(st.binary(max_size=4000), st.binary(max_size=4000))
def test_verify_rejects_garbage(pk, sig):
    with pytest.raises(QCEError):
        hybrid_verify(pk, b"m", sig, b"c")


@SET
@given(st.integers(0, 12), st.integers(0, 255), st.data())
def test_handshake_message_bitflips_never_succeed(which, xor, data):
    """Alterar cualquier byte de cualquier mensaje del handshake debe hacerlo fallar con QCEError."""
    if xor == 0:
        return
    c, s = ClientHandshake(_ident.public_bytes), ServerHandshake(_ident)
    msgs = []

    def mut(m, idx):
        pos = data.draw(st.integers(0, len(m) - 1))
        b = bytearray(m)
        b[pos] ^= xor
        return bytes(b)

    try:
        m1 = c.start()
        m1 = mut(m1, 0) if which % 4 == 0 else m1
        m2 = s.on_client_hello(m1)
        m2 = mut(m2, 1) if which % 4 == 1 else m2
        m3 = c.on_server_hello(m2)
        m3 = mut(m3, 2) if which % 4 == 2 else m3
        m4, ss = s.on_client_finish(m3)
        m4 = mut(m4, 3) if which % 4 == 3 else m4
        c.on_server_finish(m4)
    except QCEError:
        return
    # Si no hubo error, la mutación fue inocua: solo es aceptable si cayó en un campo no firmado
    # (ninguno existe en este formato) → es un fallo.
    pytest.fail("handshake aceptó un mensaje alterado")
