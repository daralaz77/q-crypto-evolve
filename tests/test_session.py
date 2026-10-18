import pytest

from qce.core.encoding import pack, unpack
from qce.core.errors import (AuthenticationFailure, PolicyViolation, QCEError, ReplayDetected)
from qce.core.policy import Policy
from qce.pqc.hybrid import HybridSigPrivateKey
from qce.protocols.session import ClientHandshake, ServerHandshake, T_CF, T_CH, T_SH


@pytest.fixture(scope="module")
def ident():
    return HybridSigPrivateKey.generate()


def handshake(ident, **kw):
    c = ClientHandshake(ident.public_bytes, **kw.get("client", {}))
    s = ServerHandshake(ident, **kw.get("server", {}))
    m1 = c.start()
    m2 = s.on_client_hello(m1)
    m3 = c.on_server_hello(m2)
    m4, ss = s.on_client_finish(m3)
    return c.on_server_finish(m4), ss


def test_full_handshake_and_bidirectional_records(ident):
    cs, ss = handshake(ident)
    assert ss.open(cs.seal(b"c->s", b"a"), b"a") == b"c->s"
    assert cs.open(ss.seal(b"s->c")) == b"s->c"


def test_reflection_is_rejected(ident):
    cs, ss = handshake(ident)
    rec = cs.seal(b"x")
    with pytest.raises(AuthenticationFailure):
        cs.open(rec)  # reenviar mi propio registro a mí mismo: dirección distinta


def test_record_replay_and_tamper(ident):
    cs, ss = handshake(ident)
    rec = cs.seal(b"pago")
    assert ss.open(rec) == b"pago"
    with pytest.raises(ReplayDetected):
        ss.open(rec)
    rec2 = bytearray(cs.seal(b"otro"))
    rec2[-1] ^= 1
    with pytest.raises(AuthenticationFailure):
        ss.open(bytes(rec2))


def test_out_of_order_within_window_ok(ident):
    cs, ss = handshake(ident)
    recs = [cs.seal(bytes([i])) for i in range(5)]
    for i in (4, 2, 0, 3, 1):
        assert ss.open(recs[i]) == bytes([i])


def test_sessions_are_independent(ident):
    cs1, ss1 = handshake(ident)
    cs2, ss2 = handshake(ident)
    with pytest.raises(AuthenticationFailure):
        ss2.open(cs1.seal(b"x"))


def test_wrong_server_identity_rejected(ident):
    impostor = HybridSigPrivateKey.generate()
    c = ClientHandshake(ident.public_bytes)
    s = ServerHandshake(impostor)
    with pytest.raises(AuthenticationFailure):
        c.on_server_hello(s.on_client_hello(c.start()))


def test_downgrade_by_mitm_on_client_hello_is_detected(ident):
    """MITM quita la suite preferida del ClientHello: la firma del servidor no coincide."""
    c = ClientHandshake(ident.public_bytes, offered=["QCE1-XMLKEM768-CHACHA", "QCE1-XMLKEM768-AESGCM"])
    s = ServerHandshake(ident)
    m1 = c.start()
    v, n, suites, q = unpack(m1, T_CH, 4)
    tampered = pack(T_CH, [v, n, b"QCE1-XMLKEM768-AESGCM", q])
    m2 = s.on_client_hello(tampered)
    with pytest.raises(AuthenticationFailure):
        c.on_server_hello(m2)


def test_server_cannot_pick_unoffered_or_forbidden_suite(ident):
    c = ClientHandshake(ident.public_bytes, offered=["QCE1-XMLKEM768-AESGCM"])
    s = ServerHandshake(ident)
    m2 = s.on_client_hello(c.start())
    v, nonce, kem, sig = unpack(m2, T_SH, 4)
    with pytest.raises(PolicyViolation):
        c.on_server_hello(pack(T_SH, [b"QCE1-XMLKEM768-CHACHA", nonce, kem, sig]))
    with pytest.raises(PolicyViolation):
        c.on_server_hello(pack(T_SH, [b"QCE0-X25519-CHACHA", nonce, kem, sig]))


def test_no_common_allowed_suite_aborts(ident):
    c = ClientHandshake(ident.public_bytes, offered=["QCE0-X25519-CHACHA"])
    with pytest.raises(PolicyViolation):
        ServerHandshake(ident).on_client_hello(c.start())


def test_policy_refuses_non_hybrid_or_forbidden_configuration():
    with pytest.raises(PolicyViolation):
        Policy(allowed_suites=("QCE0-X25519-CHACHA",))
    with pytest.raises(PolicyViolation):
        Policy().check_suite("QCE1-NOPE")


def test_tampered_client_finish_rejected(ident):
    c, s = ClientHandshake(ident.public_bytes), ServerHandshake(ident)
    m3 = c.on_server_hello(s.on_client_hello(c.start()))
    ct, mac = unpack(m3, T_CF, 2)
    bad = bytearray(ct)
    bad[-1] ^= 1
    with pytest.raises(AuthenticationFailure):
        s.on_client_finish(pack(T_CF, [bytes(bad), mac]))


def test_state_machine_order(ident):
    s = ServerHandshake(ident)
    with pytest.raises(PolicyViolation):
        s.on_client_finish(b"")
    c = ClientHandshake(ident.public_bytes)
    with pytest.raises(PolicyViolation):
        c.on_server_hello(b"")


def test_qkd_mixed_in_and_mismatch_fails(ident):
    key = b"q" * 32
    cs, ss = handshake(ident, client={"qkd": (b"id1", key)}, server={"qkd_lookup": lambda i: key})
    assert ss.open(cs.seal(b"con QKD")) == b"con QKD"
    with pytest.raises(AuthenticationFailure):  # claves QKD distintas → confirmación falla
        handshake(ident, client={"qkd": (b"id1", key)}, server={"qkd_lookup": lambda i: b"z" * 32})


def test_qkd_declared_but_missing_aborts_instead_of_downgrading(ident):
    with pytest.raises(PolicyViolation):
        handshake(ident, client={"qkd": (b"id1", b"q" * 32)})


def test_server_handshake_never_raises_foreign_exceptions(ident):
    for junk in (b"", b"\x01\x04", b"\xff" * 50, pack(T_CH, [b"QCE1", b"x" * 32, b"a,b,c", b""])):
        try:
            ServerHandshake(ident).on_client_hello(junk)
        except QCEError:
            pass
