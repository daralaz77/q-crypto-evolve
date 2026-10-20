"""Interoperabilidad con una SEGUNDA implementación independiente de TLS 1.3: GnuTLS (código distinto de OpenSSL).

La PSK externa (identidad, derivación, binder, calendario de claves en modo psk_dhe_ke) se comprueba contra GnuTLS en los dos sentidos. LÍMITE: el GnuTLS de Homebrew 3.8 no
trae X25519MLKEM768, así que aquí se usa el grupo clásico X25519 (parámetro `group`, solo para interoperar): lo que queda sin contrastar con una segunda implementación es el
grupo híbrido, que sí está atestiguado en cada conexión y probado con el cliente de OpenSSL.
"""
import shutil
import socket
import subprocess
import threading
import time

import pytest

from qce.core.errors import AuthenticationFailure, MalformedMessage, PolicyViolation
from qce.qkd.sources import OneTimeKeys
from qce.transport import tls13_psk as P

def find(name):
    """Las puertas y la mutación corren con un PATH mínimo: también se buscan las rutas habituales de Homebrew."""
    import os
    return shutil.which(name) or next((p for p in (f"/opt/homebrew/bin/{name}", f"/usr/local/bin/{name}") if os.path.exists(p)), None)


CLI, SRV = find("gnutls-cli"), find("gnutls-serv")
try:
    P._load()
    HAVE = bool(CLI and SRV)
except P.PskTransportUnavailable:
    HAVE = False
needs = pytest.mark.skipif(not HAVE, reason="sin GnuTLS (gnutls-cli/gnutls-serv) o sin OpenSSL ≥ 3.5")

KEY, KID = bytes(range(32)), b"qkd-key-0001"
SUITE, GROUP = "TLS_AES_128_GCM_SHA256", "X25519"      # la PSK externa de GnuTLS va ligada a SHA-256
PRIO = "NORMAL:-VERS-ALL:+VERS-TLS1.3:-KX-ALL:+ECDHE-PSK:-GROUP-ALL:+GROUP-X25519:-CIPHER-ALL:+AES-128-GCM"


def psk_hex(key=KEY, kid=KID):
    return P.prepare_psk(key, kid).hex()


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def listening(port):
    with socket.socket() as probe:
        return probe.connect_ex(("127.0.0.1", port)) == 0


def start_gnutls_server():
    """Arranca gnutls-serv; si el proceso muere (puerto ocupado por otro) o no escucha a tiempo, reintenta con otro puerto. Devuelve (proceso, puerto)."""
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".psk", delete=False) as f:
        f.write(f"{KID.decode()}:{psk_hex()}\n")
    for _ in range(4):
        port = free_port()
        proc = subprocess.Popen([SRV, "--port", str(port), f"--pskpasswd={f.name}", "--priority", PRIO], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        end = time.time() + 8
        while time.time() < end and proc.poll() is None and not listening(port):
            time.sleep(0.05)
        if proc.poll() is None and listening(port):
            return proc, port
        proc.kill()
        proc.wait(5)
    raise AssertionError("gnutls-serv no llegó a escuchar tras cuatro intentos")


def wait(cond, secs=4.0):
    end = time.time() + secs
    while time.time() < end and not cond():
        time.sleep(0.02)
    return cond()


def gnutls_client(port, psk, user=KID.decode(), stdin=b"ping", timeout=15):
    return subprocess.run([CLI, "--priority", PRIO, f"--pskusername={user}", f"--pskkey={psk}", "--port", str(port), "127.0.0.1"], input=stdin,
                          capture_output=True, timeout=timeout)


@needs
def test_gnutls_client_completes_the_psk_handshake_with_our_server_and_exchanges_data():
    seen = {}

    def h(conn):
        seen.update(identity=conn.identity, group=conn.group, cipher=conn.cipher, version=conn.version)
        conn._write_all(conn._read_exact(4, 5)[::-1], 5)
    store = OneTimeKeys({KID: KEY})
    srv = P.PskServer(store, h, timeout=5.0, suite=SUITE, group=GROUP).start()
    out = gnutls_client(srv.port, psk_hex())
    assert wait(lambda: "identity" in seen)
    assert seen == {"identity": KID, "group": "x25519", "cipher": "TLS_AES_128_GCM_SHA256", "version": "TLSv1.3"}
    assert b"gnip" in out.stdout and b"PSK authentication" in out.stdout + out.stderr
    assert wait(lambda: KID not in store._keys)                                  # consumida al completar
    srv.close()


@needs
def test_gnutls_client_with_a_wrong_psk_or_identity_is_rejected_and_the_key_is_kept():
    store = OneTimeKeys({KID: KEY})
    srv = P.PskServer(store, lambda c: None, timeout=3.0, suite=SUITE, group=GROUP).start()
    for psk, user in ((psk_hex(bytes(32)), KID.decode()), (psk_hex(), "otro-id")):
        out = gnutls_client(srv.port, psk, user)
        assert b"Handshake was completed" not in out.stdout + out.stderr
    assert wait(lambda: srv.failed_handshakes >= 2) and KID in store._keys and KID not in store._reserved
    srv.close()


@needs
def test_our_client_completes_the_psk_handshake_with_a_gnutls_server():
    proc, port = start_gnutls_server()
    try:
        c = P.connect_tcp("127.0.0.1", port, KID, KEY, timeout=5, suite=SUITE, group=GROUP)
        assert (c.version, c.group, c.cipher) == ("TLSv1.3", "x25519", "TLS_AES_128_GCM_SHA256")
        c._write_all(b"GET / HTTP/1.0\r\n\r\n", 5)
        assert c._read_exact(15, 5) == b"HTTP/1.0 200 OK"
        c.close()
        with pytest.raises((AuthenticationFailure, MalformedMessage)):                 # y con otra clave, GnuTLS rechaza
            P.connect_tcp("127.0.0.1", port, KID, bytes(32), timeout=5, suite=SUITE, group=GROUP)
    finally:
        proc.kill()
        proc.wait(5)


@needs
def test_our_default_hybrid_only_client_does_not_silently_downgrade_to_a_classical_group_with_gnutls():
    proc, port = start_gnutls_server()
    try:
        with pytest.raises((AuthenticationFailure, MalformedMessage, PolicyViolation)):   # GnuTLS no ofrece el híbrido: no hay grupo en común y NO se baja a X25519
            P.connect_tcp("127.0.0.1", port, KID, KEY, timeout=5, suite=SUITE)
    finally:
        proc.kill()
        proc.wait(5)


@needs
def test_group_and_suite_allowlists():
    store = OneTimeKeys({KID: KEY})
    for bad in ("X448", "secp256r1", "", "x25519"):
        with pytest.raises(PolicyViolation):
            P.connect(socket.socket(), KID, KEY, timeout=1, group=bad)       # se rechaza ANTES de tocar la red
        with pytest.raises(PolicyViolation):
            P.accept(None, store, group=bad)
    assert KID in store._keys and KID not in store._reserved
