"""TLS 1.3 estándar con PSK externa (derivada de la clave QKD) y X25519MLKEM768, por el puente ctypes de qce/transport/tls13_psk.py."""
import os
import subprocess
import threading
import time

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from qce.core.errors import AuthenticationFailure, MalformedMessage, PolicyViolation
from qce.qkd.sources import OneTimeKeys
from qce.transport import tls13_psk as P

try:
    P._load()
    HAVE_LIB = True
except P.PskTransportUnavailable:
    HAVE_LIB = False
needs_lib = pytest.mark.skipif(not HAVE_LIB, reason="sin OpenSSL ≥ 3.5 utilizable")

KEY = bytes(range(32))
KID = b"qkd-key-0001"


def echo(conn):
    conn.send_frame(conn.recv_frame()[::-1])


def serve(keys=None, handler=echo, timeout=5.0, suite=P.CIPHERSUITE):
    store = OneTimeKeys({KID: KEY} if keys is None else keys)
    return store, P.PskServer(store, handler, timeout=timeout, suite=suite).start()


def client(srv, kid=KID, key=KEY):
    return P.connect_tcp("127.0.0.1", srv.port, kid, key, timeout=5)


def wait(cond, secs=3.0):
    end = time.time() + secs
    while time.time() < end and not cond():
        time.sleep(0.02)
    return cond()


@needs_lib
def test_handshake_is_tls13_with_the_hybrid_group_the_psk_and_one_cipher_suite():
    store, srv = serve()
    c = client(srv)
    assert (c.version, c.group, c.cipher) == ("TLSv1.3", "X25519MLKEM768", "TLS_AES_256_GCM_SHA384")
    c.send_frame(b"hola psk")
    assert c.recv_frame() == b"ksp aloh"
    c.close()
    assert wait(lambda: store.reserve(KID) is None and KID not in store._keys)   # consumida al completar
    srv.close()


@needs_lib
def test_wrong_key_is_rejected_by_both_sides_and_does_not_consume_the_real_key():
    store, srv = serve()
    with pytest.raises((AuthenticationFailure, MalformedMessage)):
        client(srv, key=bytes(32))
    assert wait(lambda: srv.failed_handshakes == 1)
    assert KID in store._keys and KID not in store._reserved                        # liberada: sigue disponible
    c = client(srv)                                                                  # y el cliente legítimo completa
    c.send_frame(b"ok")
    assert c.recv_frame() == b"ko"
    c.close()
    srv.close()


@needs_lib
def test_unknown_identity_fails_and_touches_nothing():
    store, srv = serve()
    with pytest.raises((AuthenticationFailure, MalformedMessage)):
        client(srv, kid=b"no-existe")
    assert wait(lambda: srv.failed_handshakes == 1) and KID in store._keys and KID not in store._reserved
    srv.close()


@needs_lib
def test_a_completed_key_cannot_be_used_twice():
    store, srv = serve()
    c = client(srv)
    c.send_frame(b"x")
    c.recv_frame()
    c.close()
    assert wait(lambda: KID not in store._keys)
    with pytest.raises((AuthenticationFailure, MalformedMessage)):
        client(srv)
    srv.close()


@needs_lib
def test_concurrent_clients_with_distinct_keys_all_complete_and_use_their_own_key():
    keys = {b"k%d" % i: bytes([i + 1]) * 32 for i in range(8)}
    seen = []
    lock = threading.Lock()

    def h(conn):
        with lock:
            seen.append(conn.identity)
        echo(conn)
    store, srv = serve(keys, h)
    out = {}

    def run(kid):
        c = client(srv, kid, keys[kid])
        c.send_frame(kid)
        out[kid] = c.recv_frame()
        c.close()
    ts = [threading.Thread(target=run, args=(k,)) for k in keys]
    [t.start() for t in ts]
    [t.join(10) for t in ts]
    assert out == {k: k[::-1] for k in keys} and sorted(seen) == sorted(keys)
    srv.close()


@needs_lib
def test_silent_client_is_dropped_at_the_handshake_timeout_and_holds_nothing():
    import socket
    store, srv = serve(timeout=1.0)
    s = socket.create_connection(("127.0.0.1", srv.port))
    assert wait(lambda: srv.failed_handshakes == 1, 4.0) and KID in store._keys and KID not in store._reserved
    s.close()
    srv.close()


@needs_lib
def test_third_party_openssl_client_completes_the_same_handshake():
    """Interoperabilidad: el cliente de línea de órdenes de OpenSSL (otra implementación del cliente) usa la PSK derivada y el grupo híbrido."""
    exe = next((p for p in (os.popen("command -v openssl").read().strip(), "/opt/homebrew/bin/openssl", "/opt/homebrew/opt/openssl@3/bin/openssl")
                if p and os.path.exists(p) and "X25519MLKEM768" in subprocess.run([p, "list", "-kem-algorithms"], capture_output=True, text=True).stdout), None)
    if not exe:
        pytest.skip("sin openssl con X25519MLKEM768")
    got = {}

    def h(conn):
        got["id"], got["group"], got["cipher"] = conn.identity, conn.group, conn.cipher
    store, srv = serve(handler=h, suite="TLS_AES_128_GCM_SHA256")   # la PSK externa de la herramienta de OpenSSL va ligada a SHA-256
    psk = P.prepare_psk(KEY, KID).hex()
    subprocess.run([exe, "s_client", "-connect", f"127.0.0.1:{srv.port}", "-tls1_3", "-groups", "X25519MLKEM768", "-ciphersuites", "TLS_AES_128_GCM_SHA256",
                    "-psk", psk, "-psk_identity", KID.decode()], input=b"", capture_output=True, timeout=20)
    assert wait(lambda: "id" in got)
    assert got == {"id": KID, "group": "X25519MLKEM768", "cipher": "TLS_AES_128_GCM_SHA256"}
    srv.close()


@needs_lib
def test_third_party_openssl_client_with_a_wrong_psk_is_rejected():
    exe = "/opt/homebrew/bin/openssl"
    if not os.path.exists(exe):
        pytest.skip("sin openssl de Homebrew")
    store, srv = serve(suite="TLS_AES_128_GCM_SHA256")
    subprocess.run([exe, "s_client", "-connect", f"127.0.0.1:{srv.port}", "-tls1_3", "-groups", "X25519MLKEM768", "-ciphersuites", "TLS_AES_128_GCM_SHA256", "-psk", "00" * 32, "-psk_identity", KID.decode()],
                   input=b"", capture_output=True, timeout=20)
    assert wait(lambda: srv.failed_handshakes == 1) and KID in store._keys
    srv.close()


def test_psk_derivation_matches_the_documented_formula_independently():
    def lp(x):
        return len(x).to_bytes(4, "big") + x
    expect = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"QCE/TLS13-PSK/1" + lp(KID)).derive(KEY)
    assert P.prepare_psk(KEY, KID) == expect
    assert P.prepare_psk(KEY, b"otro") != expect and P.prepare_psk(bytes(32), KID) != expect


def test_inputs_are_validated_at_their_limits():
    for bad in (KEY[:P.QKD_KEY_MIN - 1], bytes(P.QKD_KEY_MAX + 1)):
        with pytest.raises(PolicyViolation):
            P.prepare_psk(bad, KID)
    P.prepare_psk(bytes(P.QKD_KEY_MIN), KID)
    P.prepare_psk(bytes(P.QKD_KEY_MAX), KID)
    for bad in (b"", bytes(P.IDENT_MAX + 1)):
        with pytest.raises(MalformedMessage):
            P.prepare_psk(KEY, bad)
    P.prepare_psk(KEY, b"k")
    P.prepare_psk(KEY, bytes(P.IDENT_MAX))


def test_transport_fails_closed_without_a_usable_openssl(monkeypatch):
    monkeypatch.setattr(P, "_lib_cache", None)
    monkeypatch.setattr(P, "_CANDIDATES", ("/no/existe/libssl.so.3",))
    with pytest.raises(P.PskTransportUnavailable):
        P._load()
    monkeypatch.setattr(P, "_CANDIDATES", tuple(c for c in P._CANDIDATES) or ("x",))
    monkeypatch.setattr(P, "_lib_cache", None)


@needs_lib
def test_too_old_openssl_is_refused(monkeypatch):
    real = P._lib_cache
    monkeypatch.setattr(P, "_lib_cache", None)
    monkeypatch.setattr(P, "OPENSSL_MIN", 0xFFFFFFFF)
    with pytest.raises(P.PskTransportUnavailable):
        P._load()
    monkeypatch.setattr(P, "_lib_cache", real)


@needs_lib
@pytest.mark.parametrize("attr,value", [("group", "X25519"), ("version", "TLSv1.2"), ("cipher", "TLS_CHACHA20_POLY1305_SHA256"), ("psk_used", False)])
def test_attestation_closes_the_connection_if_what_was_negotiated_is_not_what_was_required(monkeypatch, attr, value):
    store, srv = serve()
    monkeypatch.setattr(P.PskTlsConnection, attr, property(lambda self, v=value: v))
    with pytest.raises(PolicyViolation):
        client(srv)
    assert wait(lambda: srv.failed_handshakes == 1)                         # el servidor también atestigua y cierra
    assert KID in store._keys and KID not in store._reserved                # y devuelve la clave: el apretón no se completó
    srv.close()


@needs_lib
def test_frames_respect_their_limits_and_a_closed_peer_is_reported():
    got = {}

    def h(conn):
        try:
            got["data"] = conn.recv_frame(max_size=10)
        except MalformedMessage as e:
            got["err"] = str(e)
    store, srv = serve(handler=h)
    c = client(srv)
    c.send_frame(bytes(11))
    assert wait(lambda: "err" in got) and "máximo" in got["err"]
    with pytest.raises(MalformedMessage):
        c.send_frame(bytes(P.MAX_FRAME + 1))
    c.close()
    srv.close()
    store, srv = serve(handler=lambda conn: None)   # el servidor cierra al terminar el manejador
    c = client(srv)
    with pytest.raises(MalformedMessage):
        c.recv_frame()
    srv.close()


@needs_lib
def test_only_the_two_standard_suites_are_allowed():
    store, srv = serve()
    for bad in ("TLS_CHACHA20_POLY1305_SHA256", "", "NULL"):
        with pytest.raises(PolicyViolation):
            P.connect_tcp("127.0.0.1", srv.port, KID, KEY, timeout=5, suite=bad)
    srv.close()
    store = OneTimeKeys({KID: KEY})
    with pytest.raises(PolicyViolation):
        P.accept(None, store, suite="otra")
    assert KID in store._keys and KID not in store._reserved


@needs_lib
def test_a_suite_mismatch_between_the_two_ends_does_not_connect():
    store, srv = serve(suite="TLS_AES_128_GCM_SHA256")
    with pytest.raises((AuthenticationFailure, MalformedMessage)):
        client(srv)
    assert wait(lambda: srv.failed_handshakes == 1) and KID in store._keys and KID not in store._reserved
    srv.close()


@needs_lib
def test_a_reserved_key_cannot_be_used_by_a_second_connection_until_the_first_commits_or_releases():
    gate, inside = threading.Event(), threading.Event()

    class Slow(OneTimeKeys):
        def commit(self, k):
            inside.set()
            gate.wait(5)
            super().commit(k)
    store = Slow({KID: KEY})
    srv = P.PskServer(store, echo, timeout=5.0).start()
    first = {}
    t = threading.Thread(target=lambda: first.setdefault("c", client(srv)))
    t.start()
    assert inside.wait(5)                              # el servidor ya completó el apretón y está confirmando: la clave sigue reservada
    with pytest.raises((AuthenticationFailure, MalformedMessage)):
        client(srv)                                    # el segundo uso del mismo id no entra
    gate.set()
    t.join(5)
    first["c"].send_frame(b"ab")
    assert first["c"].recv_frame() == b"ba"
    first["c"].close()
    srv.close()


@needs_lib
def test_server_discards_a_key_the_source_hands_over_out_of_range():
    store, srv = serve({KID: KEY[:P.QKD_KEY_MIN - 1]})
    with pytest.raises((AuthenticationFailure, MalformedMessage)):
        client(srv)
    assert wait(lambda: srv.failed_handshakes == 1) and KID not in store._keys   # inservible: se descarta, no queda reservada ni disponible
    srv.close()


@needs_lib
def test_a_stale_openssl_error_in_the_thread_does_not_break_a_healthy_connection():
    """La cola de errores de OpenSSL es por hilo y SSL_read no la limpia: un error previo (p. ej. del cierre de otra conexión) no puede romper una lectura sana."""
    lib, crypto = P._load()

    def slow_echo(conn):
        data = conn.recv_frame()
        time.sleep(0.4)                                 # la primera lectura del cliente devuelve «esperar datos» y pasa por SSL_get_error
        conn.send_frame(data[::-1])
    store, srv = serve(handler=slow_echo)
    c = client(srv)
    c.send_frame(b"ab")
    ctx = P._new_ctx((lib, crypto), False, P.CIPHERSUITE)
    assert lib.SSL_CTX_set_ciphersuites(ctx, b"NO-EXISTE") == 0                 # deja un error en la cola de ESTE hilo, justo antes de leer
    lib.SSL_CTX_free(ctx)
    assert c.recv_frame() == b"ba"
    c.close()
    srv.close()
