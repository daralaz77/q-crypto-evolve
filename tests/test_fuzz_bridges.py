"""Fuzzing de los puentes ctypes (TLS 1.3 con PSK y SLH-DSA): entradas hostiles solo pueden producir errores TIPADOS, nunca bloqueos, caídas ni éxitos.

Lo que se comprueba: (1) una ClientHello válida con UN bit cambiado jamás completa el apretón y no gasta la clave (el binder de la PSK cubre el mensaje);
(2) un servidor hostil que contesta basura, trunca o calla no cuelga ni rompe al cliente; (3) marcos con longitudes mentirosas; (4) SLH-DSA ante bytes arbitrarios.
"""
import random
import socket
import struct
import threading
import time

import pytest
from hypothesis import HealthCheck, given, settings, strategies as st

from qce.core.errors import AuthenticationFailure, MalformedMessage, PolicyViolation
from qce.pqc import slhdsa as S
from qce.qkd.sources import OneTimeKeys
from qce.transport import tls13_psk as P

try:
    P._load()
    HAVE = True
except P.PskTransportUnavailable:
    HAVE = False
needs = pytest.mark.skipif(not HAVE, reason="sin OpenSSL ≥ 3.5")
KEY, KID = bytes(range(32)), b"qkd-key-0001"
TYPED = (AuthenticationFailure, MalformedMessage, PolicyViolation, TimeoutError)


def wait(cond, secs=4.0):
    end = time.time() + secs
    while time.time() < end and not cond():
        time.sleep(0.02)
    return cond()


def capture_client_hello():
    """Lo primero que envía un cliente real: un servidor TCP que lo lee y cierra."""
    ls = socket.socket()
    ls.bind(("127.0.0.1", 0))
    ls.listen(1)
    box = {}

    def serve():
        c, _ = ls.accept()
        c.settimeout(3)
        buf = b""
        try:
            while True:
                chunk = c.recv(8192)
                if not chunk:
                    break
                buf += chunk
                if len(buf) >= 5 and len(buf) >= 5 + struct.unpack(">H", buf[3:5])[0]:
                    break
        except OSError:
            pass
        box["hello"] = buf
        c.close()
    t = threading.Thread(target=serve)
    t.start()
    try:
        P.connect_tcp("127.0.0.1", ls.getsockname()[1], KID, KEY, timeout=3)
    except (*TYPED, OSError):
        pass
    t.join(5)
    ls.close()
    return box["hello"]


def raw_send(port, data, read_secs=1.5):
    s = socket.create_connection(("127.0.0.1", port), timeout=3)
    try:
        s.sendall(data)
        s.settimeout(read_secs)
        try:
            while s.recv(65536):
                pass
        except (OSError, socket.timeout):
            pass
    finally:
        s.close()


@needs
def test_a_valid_client_hello_with_one_flipped_bit_never_completes_and_never_burns_the_key():
    hello = capture_client_hello()
    assert hello[0] == 0x16 and len(hello) > 1000                       # registro de apretón con la clave ML-KEM dentro
    completed = []
    store = OneTimeKeys({KID: KEY})
    srv = P.PskServer(store, lambda c: completed.append(c.identity), timeout=1.0).start()
    rng = random.Random(20261019)
    positions = sorted({5, 6, 40, len(hello) - 1, len(hello) - 40, *(rng.randrange(5, len(hello)) for _ in range(34))})   # dentro del mensaje, incl. el binder
    for i, pos in enumerate(positions, 1):
        bad = bytearray(hello)
        bad[pos] ^= 1 << rng.randrange(8)
        raw_send(srv.port, bytes(bad))
        assert wait(lambda: srv.failed_handshakes >= i), f"posición {pos}: el servidor no rechazó el mensaje"
    assert completed == [] and KID in store._keys and KID not in store._reserved
    srv.close()


@needs
def test_replaying_an_unmodified_client_hello_does_not_complete_without_the_psk_finished():
    hello = capture_client_hello()
    completed = []
    store = OneTimeKeys({KID: KEY})
    srv = P.PskServer(store, lambda c: completed.append(1), timeout=1.0).start()
    raw_send(srv.port, hello, read_secs=2.5)                              # el atacante no puede producir el Finished del cliente
    assert wait(lambda: srv.failed_handshakes == 1, 4.0) and completed == []
    assert KID in store._keys and KID not in store._reserved               # y la clave vuelve a estar disponible tras el plazo
    srv.close()


@needs
def test_garbage_record_headers_and_truncations_are_survived_and_leave_the_server_usable():
    store = OneTimeKeys({KID: KEY})
    srv = P.PskServer(store, lambda c: c.send_frame(c.recv_frame()[::-1]), timeout=0.8).start()
    rng = random.Random(7)
    cases = [b"", b"\x16", b"\x16\x03\x01", b"\x16\x03\x01\x00\x05abc", b"\x16\x03\x01\xff\xff" + bytes(100), b"\x15\x03\x03\x00\x02\x02\x28",
             b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", bytes(2000), b"\xff" * 1000, b"\x16\x03\x03\x40\x00" + bytes(rng.randrange(256) for _ in range(300))] + \
            [bytes(rng.randrange(256) for _ in range(rng.choice([1, 4, 5, 37, 512, 9000]))) for _ in range(12)]
    for data in cases:
        raw_send(srv.port, data, read_secs=1.0)
    assert wait(lambda: srv.failed_handshakes >= len(cases) - 1, 12.0)
    assert KID in store._keys and KID not in store._reserved
    c = P.connect_tcp("127.0.0.1", srv.port, KID, KEY, timeout=5)          # tras todo eso, el servidor sigue atendiendo a un cliente legítimo
    c.send_frame(b"ab")
    assert c.recv_frame() == b"ba"
    c.close()
    srv.close()


@needs
@pytest.mark.parametrize("behaviour", ["garbage_small", "garbage_big", "alert", "header_then_silence", "close_immediately", "silent", "slow_drip", "http"])
def test_a_hostile_server_cannot_hang_crash_or_trick_the_client(behaviour):
    ls = socket.socket()
    ls.bind(("127.0.0.1", 0))
    ls.listen(2)

    def serve():
        try:
            c, _ = ls.accept()
            c.settimeout(2)
            try:
                c.recv(8192)
            except OSError:
                pass
            if behaviour == "garbage_small":
                c.sendall(bytes(range(40)))
            elif behaviour == "garbage_big":
                c.sendall(random.Random(1).randbytes(70000))
            elif behaviour == "alert":
                c.sendall(b"\x15\x03\x03\x00\x02\x02\x28")
            elif behaviour == "header_then_silence":
                c.sendall(b"\x16\x03\x03\x10\x00" + bytes(20))
                time.sleep(3)
            elif behaviour == "slow_drip":
                for _ in range(8):
                    c.sendall(b"\x16")
                    time.sleep(0.4)
            elif behaviour == "http":
                c.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            elif behaviour == "silent":
                time.sleep(3)
            c.close()
        except OSError:
            pass
    t = threading.Thread(target=serve, daemon=True)
    t.start()
    t0 = time.monotonic()
    with pytest.raises((*TYPED, OSError)) as e:
        P.connect_tcp("127.0.0.1", ls.getsockname()[1], KID, KEY, timeout=1.5)
    assert time.monotonic() - t0 < 6.0, "el cliente tardó mucho más que su plazo"
    assert "ESCAPE" not in repr(e.value)
    ls.close()


@needs
@pytest.mark.parametrize("header", [struct.pack(">I", P.MAX_FRAME + 1), struct.pack(">I", 0xFFFFFFFF), struct.pack(">I", 1 << 31)])
def test_frames_with_lying_lengths_are_refused_without_allocating(header):
    store = OneTimeKeys({KID: KEY})
    srv = P.PskServer(store, lambda c: c._write_all(header, 5), timeout=3.0).start()
    c = P.connect_tcp("127.0.0.1", srv.port, KID, KEY, timeout=5)
    with pytest.raises(MalformedMessage):
        c.recv_frame(timeout=5)
    c.close()
    srv.close()


@needs
def test_truncated_frames_and_empty_frames():
    store = OneTimeKeys({KID: KEY})
    srv = P.PskServer(store, lambda c: c._write_all(struct.pack(">I", 100) + b"solo diez!", 5), timeout=3.0).start()
    c = P.connect_tcp("127.0.0.1", srv.port, KID, KEY, timeout=5)
    with pytest.raises(MalformedMessage):
        c.recv_frame(timeout=5)                                        # el par cierra a mitad de un mensaje
    c.close()
    srv.close()
    store = OneTimeKeys({KID: KEY})
    srv = P.PskServer(store, lambda c: c.send_frame(b""), timeout=3.0).start()
    c = P.connect_tcp("127.0.0.1", srv.port, KID, KEY, timeout=5)
    assert c.recv_frame(timeout=5) == b""
    c.close()
    srv.close()


# ---- SLH-DSA --------------------------------------------------------------------------------------------------------
SLOW = settings(max_examples=60, deadline=None, suppress_health_check=[HealthCheck.too_slow])


@given(st.binary(max_size=80), st.binary(max_size=9000), st.binary(max_size=400), st.binary(max_size=300))
@SLOW
def test_slhdsa_verify_on_arbitrary_bytes_only_raises_typed_errors(pk, sig, msg, ctx):
    try:
        S.slhdsa_verify(pk, msg, sig, ctx)
    except (AuthenticationFailure, MalformedMessage):
        return
    raise AssertionError("una entrada aleatoria fue aceptada")


@given(st.integers(0, 2**32 - 1), st.integers(0, 2000), st.integers(0, 255))
@SLOW
def test_slhdsa_random_well_formed_inputs_are_rejected(seed, msg_len, ctx_len):
    rng = random.Random(seed)       # bytes bien formados (longitudes exactas) generados desde una semilla: Hypothesis no admite bien entradas fijas de 8 KB
    with pytest.raises(AuthenticationFailure):
        S.slhdsa_verify(rng.randbytes(S.PK_LEN), rng.randbytes(msg_len), rng.randbytes(S.SIG_LEN), rng.randbytes(ctx_len))


@pytest.fixture(scope="module")
def slh():
    k = S.SlhDsaPrivateKey.generate()
    return k, k.sign(b"mensaje de referencia", b"c")


@given(st.integers(0, S.SIG_LEN - 1), st.integers(0, 7))
@settings(max_examples=120, deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture])
def test_slhdsa_any_single_bit_flip_in_a_valid_signature_is_rejected(slh, pos, bit):
    k, sig = slh
    bad = bytearray(sig)
    bad[pos] ^= 1 << bit
    with pytest.raises(AuthenticationFailure):
        S.slhdsa_verify(k.public_bytes(), b"mensaje de referencia", bytes(bad), b"c")


@given(st.binary(max_size=3000), st.binary(max_size=255))
@settings(max_examples=12, deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_slhdsa_sign_then_verify_roundtrips_for_arbitrary_messages_and_contexts(msg, ctx):
    k = S.SlhDsaPrivateKey.generate()
    sig = k.sign(msg, ctx)
    S.slhdsa_verify(k.public_bytes(), msg, sig, ctx)
    if ctx:
        with pytest.raises(AuthenticationFailure):
            S.slhdsa_verify(k.public_bytes(), msg, sig, ctx[:-1])
