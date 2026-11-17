"""Ronda 4 de auditoría (2026-11-16): tres defectos y su prueba de regresión.

1. QCE1: un ClientHello (sin autenticar) que nombraba una clave QKD válida la GASTABA si el consumidor era `KeyBroker.take`. Ahora el servidor la RESERVA
   al recibirlo, la consume solo cuando el MAC del cliente demuestra que la posee y la devuelve si el apretón falla o se abandona.
2. ETSI-014: el certificado fijado del KME solo se comprobaba una vez, en otra conexión, al dar de alta. Ahora cada petición lo exige en SU conexión.
3. `atomic_write` filtraba el descriptor si `fchmod` o `fdopen` fallaban, y no tenía ninguna prueba directa.
"""
import hashlib
import os

import pytest

from qce.core import atomic
from qce.core.errors import AuthenticationFailure, PolicyViolation
from qce.pqc.hybrid import HybridSigPrivateKey
from qce.protocols.session import ClientHandshake, ServerHandshake
from qce.qkd.contract import ErrorCategory, QKDDeviceError
from qce.qkd.etsi014 import HttpsTransport
from qce.qkd.etsi014_emulator import EmulatedKME
from qce.qkd.sources import OneTimeKeys
from qce.transport import pki

from tests.test_etsi014 import MASTER, SLAVE, brokers, client_ctx, env, server_ctx  # noqa: F401  (env es un fixture)

KID, KEY = b"kid-0001", b"k" * 32


@pytest.fixture(scope="module")
def ident():
    return HybridSigPrivateKey.generate()


def _server(ident, source):
    return ServerHandshake(ident, qkd_source=source)


# ---- 1. QCE1: la clave QKD solo se consume cuando el cliente demuestra poseerla ---------------------------------------------------------------
def test_an_unauthenticated_client_hello_reserves_the_key_but_does_not_burn_it(ident):
    src = OneTimeKeys({KID: KEY})
    victim = ClientHandshake(ident.public_bytes, qkd=(KID, KEY)).start()   # un ClientHello cualquiera que nombra una clave válida
    s = _server(ident, src)
    s.on_client_hello(victim)
    assert src.reserve(KID) is None                                         # reservada: nadie más la obtiene mientras el apretón sigue abierto
    s.abort()                                                               # el atacante nunca contestó
    assert src.reserve(KID) == KEY                                          # sigue intacta: no se gastó
    src.release(KID)


def test_a_client_that_does_not_know_the_key_cannot_consume_it(ident):
    src = OneTimeKeys({KID: KEY})
    s = _server(ident, src)
    impostor = ClientHandshake(ident.public_bytes, qkd=(KID, b"z" * 32))   # conoce el identificador, no la clave
    m3 = impostor.on_server_hello(s.on_client_hello(impostor.start()))
    with pytest.raises(AuthenticationFailure):
        s.on_client_finish(m3)
    assert src.reserve(KID) == KEY                                          # el fallo la devolvió, entera
    src.release(KID)
    legit = ClientHandshake(ident.public_bytes, qkd=(KID, KEY))            # y el titular legítimo sigue pudiendo usarla
    s2 = _server(ident, src)
    m3 = legit.on_server_hello(s2.on_client_hello(legit.start()))
    m4, ss = s2.on_client_finish(m3)
    cs = legit.on_server_finish(m4)
    assert ss.open(cs.seal(b"ok")) == b"ok"


def test_a_completed_handshake_consumes_the_key_exactly_once(ident):
    src = OneTimeKeys({KID: KEY})
    c = ClientHandshake(ident.public_bytes, qkd=(KID, KEY))
    s = _server(ident, src)
    m4, ss = s.on_client_finish(c.on_server_hello(s.on_client_hello(c.start())))
    c.on_server_finish(m4)
    src.release(KID)                                                        # aunque alguien intente devolverla, ya no existe: se consumió (no solo se reservó)
    assert src.reserve(KID) is None
    s.abort()                                                               # abortar después del éxito tampoco la devuelve
    assert src.reserve(KID) is None
    with pytest.raises(PolicyViolation):                                    # y una segunda sesión con la misma clave se rechaza
        _server(ident, src).on_client_hello(ClientHandshake(ident.public_bytes, qkd=(KID, KEY)).start())


def test_a_replayed_client_hello_cannot_hold_or_burn_the_key_beyond_the_open_handshake(ident):
    src = OneTimeKeys({KID: KEY})
    m1 = ClientHandshake(ident.public_bytes, qkd=(KID, KEY)).start()
    first, second = _server(ident, src), _server(ident, src)
    first.on_client_hello(m1)
    with pytest.raises(PolicyViolation):                                    # mientras el primero está abierto, la repetición no obtiene la clave
        second.on_client_hello(m1)
    first.abort()
    second.on_client_hello(m1)                                              # liberada: ahora sí (y sin haberse gastado)
    second.abort()
    assert src.reserve(KID) == KEY


def test_qkd_declared_but_missing_still_aborts_with_a_source_and_lookup_and_source_are_exclusive(ident):
    with pytest.raises(PolicyViolation):
        _server(ident, OneTimeKeys()).on_client_hello(ClientHandshake(ident.public_bytes, qkd=(KID, KEY)).start())
    with pytest.raises(PolicyViolation):
        ServerHandshake(ident, qkd_lookup=lambda _i: KEY, qkd_source=OneTimeKeys())


def test_abort_is_idempotent_and_closes_the_handshake(ident):
    src = OneTimeKeys({KID: KEY})
    c = ClientHandshake(ident.public_bytes, qkd=(KID, KEY))
    s = _server(ident, src)
    m3 = c.on_server_hello(s.on_client_hello(c.start()))
    s.abort()
    s.abort()
    assert src.reserve(KID) == KEY
    with pytest.raises(PolicyViolation, match="fuera de orden"):            # tras abortar ya no se acepta el final del cliente
        s.on_client_finish(m3)


# ---- 2. ETSI-014: el certificado fijado se exige en CADA petición, en su propia conexión ---------------------------------------------------------
def test_a_kme_with_another_certificate_gets_no_request_after_the_device_was_authenticated(env):  # noqa: F811
    b, ad, _ = brokers(env)["master"]
    b.attach("L1", ad)                                                      # superó la comprobación del alta: el certificado queda fijado
    assert ad.get_health_status()["state"] == "OK"                          # con el certificado fijado funciona
    cert2, key2 = pki.issue_leaf(env.tmp, env.ck, env.cc, "kme2.lab", server=True)   # otro certificado, firmado por la MISMA CA
    kme2 = EmulatedKME(server_ctx(cert2, key2, env.ca), MASTER, SLAVE).start()
    try:
        ad._t._port = kme2.port                                             # el extremo "cambia" de certificado tras el alta
        with pytest.raises(QKDDeviceError) as e:
            ad.get_health_status()
        assert e.value.category is ErrorCategory.DEVICE_UNTRUSTED
        assert kme2.requests == []                                          # no recibió NI la petición: se cortó antes de enviarla
    finally:
        kme2.close()


def test_an_unpinned_transport_sends_nothing_and_a_pin_is_a_sha256_fingerprint(env):  # noqa: F811
    tr = HttpsTransport("127.0.0.1", env.kme.port, client_ctx(env.ca, *env.certs[MASTER]), timeout=3)
    with pytest.raises(QKDDeviceError) as e:
        tr.request("GET", f"/api/v1/keys/{SLAVE}/status")
    assert e.value.category is ErrorCategory.DEVICE_UNTRUSTED
    assert env.kme.requests == []
    for bad in (b"corta", "x" * 32, None, b"\x00" * 33):
        with pytest.raises(QKDDeviceError):
            tr.set_pin(bad)
    tr.set_pin(env.fp)
    status, _ = tr.request("GET", f"/api/v1/keys/{SLAVE}/status")
    assert status == 200
    tr.set_pin(hashlib.sha256(b"otro").digest())
    with pytest.raises(QKDDeviceError) as e:
        tr.request("GET", f"/api/v1/keys/{SLAVE}/status")
    assert e.value.category is ErrorCategory.DEVICE_UNTRUSTED
    assert len(env.kme.requests) == 1                                       # solo la de la huella correcta


# ---- 3. atomic_write -------------------------------------------------------------------------------------------------------------------------
def _open_fds() -> int:
    return len(os.listdir("/dev/fd"))


def test_atomic_write_writes_replaces_and_leaves_no_temporaries(tmp_path):
    p = tmp_path / "f.bin"
    atomic.atomic_write(p, b"uno")
    atomic.atomic_write(p, b"dos", mode=0o644)
    assert p.read_bytes() == b"dos" and (p.stat().st_mode & 0o777) == 0o644
    assert [x.name for x in tmp_path.iterdir()] == ["f.bin"]


def test_atomic_write_mode_is_exact_even_with_a_permissive_umask(tmp_path):
    old = os.umask(0)
    try:
        atomic.atomic_write(tmp_path / "k", b"s")
    finally:
        os.umask(old)
    assert ((tmp_path / "k").stat().st_mode & 0o777) == 0o600


@pytest.mark.parametrize("target", ["fchmod", "fdopen"])
def test_atomic_write_does_not_leak_the_descriptor_nor_touch_the_target_when_setup_fails(tmp_path, monkeypatch, target):
    p = tmp_path / "f.bin"
    p.write_bytes(b"original")

    def boom(*a, **k):
        raise OSError("fallo inyectado")
    monkeypatch.setattr(os, target, boom)
    before = _open_fds()
    for _ in range(5):
        with pytest.raises(OSError, match="inyectado"):
            atomic.atomic_write(p, b"nuevo")
    assert _open_fds() == before                                            # ningún descriptor filtrado
    assert p.read_bytes() == b"original" and [x.name for x in tmp_path.iterdir()] == ["f.bin"]


def test_atomic_write_failure_during_the_rename_keeps_the_old_file_and_cleans_up(tmp_path, monkeypatch):
    p = tmp_path / "f.bin"
    p.write_bytes(b"original")
    monkeypatch.setattr(os, "replace", lambda *a, **k: (_ for _ in ()).throw(OSError("sin espacio")))
    before = _open_fds()
    with pytest.raises(OSError, match="sin espacio"):
        atomic.atomic_write(p, b"nuevo")
    assert _open_fds() == before and p.read_bytes() == b"original" and [x.name for x in tmp_path.iterdir()] == ["f.bin"]
