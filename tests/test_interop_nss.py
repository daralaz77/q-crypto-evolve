"""Interoperabilidad con una SEGUNDA implementación independiente que SÍ trae el híbrido: Mozilla NSS (código distinto de OpenSSL y de GnuTLS).

Qué contrasta con NSS (las herramientas `tstclnt` y `selfserv` de NSS ≥ 3.125):
  · el grupo híbrido X25519MLKEM768 con PSK externa: cliente NSS contra nuestro servidor PSK, y rechazo con PSK o identidad equivocadas;
  · que no hay bajada silenciosa: un cliente NSS que solo ofrece X25519 no completa el apretón con nuestro servidor híbrido;
  · el híbrido con certificados en el otro sentido: nuestro cliente TLS contra `selfserv` de NSS, y la negativa a usar un NSS que solo ofrece X25519.
La ruta con la clave en el HSM está en `tests/test_hsm_tls.py` (escenario `nss`).

LÍMITES, medidos y no supuestos:
  · `selfserv` exige un certificado y, teniéndolo, autentica con él aunque se le dé una PSK (incluso frente a `tstclnt`), así que NO sirve para probar NUESTRO CLIENTE PSK
    contra un servidor NSS: ese sentido de la PSK externa solo está contrastado con GnuTLS (X25519) y con OpenSSL.
  · La PSK externa de NSS va ligada a SHA-256, como la de OpenSSL y GnuTLS: con nuestra suite por defecto (AES-256-GCM-SHA384) NSS no completa el apretón (se prueba).
"""
import os
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path

import pytest

from qce.core.errors import AuthenticationFailure, MalformedMessage, PolicyViolation
from qce.qkd.sources import OneTimeKeys
from qce.transport import tls13, tls13_psk as P


def find(name):
    """Las puertas y la mutación corren con un PATH mínimo: se buscan también las rutas habituales de Homebrew."""
    return shutil.which(name) or next((p for p in (f"/opt/homebrew/opt/nss/bin/{name}", f"/usr/local/opt/nss/bin/{name}", f"/opt/homebrew/bin/{name}") if os.path.exists(p)), None)


CERTUTIL, TSTCLNT, SELFSERV = find("certutil"), find("tstclnt"), find("selfserv")
try:
    P._load()
    HAVE = bool(CERTUTIL and TSTCLNT and SELFSERV)
except P.PskTransportUnavailable:
    HAVE = False
needs = pytest.mark.skipif(not HAVE, reason="sin NSS (certutil, tstclnt, selfserv) o sin OpenSSL ≥ 3.5")

KEY, KID = bytes(range(32)), b"qkd-key-0001"
SUITE = "TLS_AES_128_GCM_SHA256"      # la PSK externa de NSS va ligada a SHA-256


def psk_hex(key=KEY, kid=KID):
    """Derivación INDEPENDIENTE de la de producción (HKDF-SHA256, etiqueta de dominio, identificador con prefijo de longitud): NSS recibe esta PSK, así que si `prepare_psk`
    cambiase la etiqueta, el orden o el hash, NSS y nuestro servidor dejarían de coincidir y la prueba fallaría. Con `prepare_psk` en los dos lados no fijaría nada."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"QCE/TLS13-PSK/1" + len(kid).to_bytes(4, "big") + kid).derive(key).hex()


def wait(cond, secs=4.0):
    end = time.time() + secs
    while time.time() < end and not cond():
        time.sleep(0.02)
    return cond()


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def nss_db(tmp: Path, name="db") -> str:
    d = tmp / name
    d.mkdir()
    subprocess.run([CERTUTIL, "-N", "-d", f"sql:{d}", "--empty-password"], check=True, capture_output=True, timeout=60)
    return f"sql:{d}"


def nss_client(port, db, groups, psk=None, label=KID.decode(), data=b"ping"):
    cmd = [TSTCLNT, "-d", db, "-h", "127.0.0.1", "-p", str(port), "-V", "tls1.3:tls1.3", "-I", groups, "-o"]
    if psk is not None:
        cmd += ["-z", f"0x{psk}:{label}"]
    out = subprocess.run(cmd, input=data, capture_output=True, timeout=20)
    return (out.stdout + out.stderr).decode(errors="replace")


def psk_server(handler=None, suite=SUITE, **kw):
    seen = {}

    def h(c):
        seen.update(identity=c.identity, group=c.group, cipher=c.cipher, version=c.version)
        try:
            c._write_all(c._read_exact(4, 5)[::-1], 5)
        except Exception as exc:   # noqa: BLE001
            seen["io"] = type(exc).__name__
    store = OneTimeKeys({KID: KEY})
    return P.PskServer(store, handler or h, timeout=5.0, suite=suite, **kw).start(), store, seen


@needs
def test_nss_client_completes_the_hybrid_psk_handshake_with_our_server():
    with tempfile.TemporaryDirectory() as td:
        srv, store, seen = psk_server()
        out = nss_client(srv.port, nss_db(Path(td)), "x25519mlkem768", psk_hex())
        assert wait(lambda: "identity" in seen)
        assert (seen["identity"], seen["group"], seen["cipher"], seen["version"]) == (KID, "X25519MLKEM768", SUITE, "TLSv1.3")   # lo atestigua NUESTRO servidor
        assert "gnip" in out                                                  # NSS recibió la respuesta cifrada
        assert wait(lambda: KID not in store._keys)                           # la clave QKD se consumió al completar
        srv.close()


@needs
def test_nss_client_with_a_wrong_psk_or_label_is_rejected_and_the_key_is_kept():
    with tempfile.TemporaryDirectory() as td:
        db = nss_db(Path(td))
        srv, store, seen = psk_server()
        for psk, label in ((psk_hex(bytes(32)), KID.decode()), (psk_hex(), "otro-id")):
            assert "gnip" not in nss_client(srv.port, db, "x25519mlkem768", psk, label)
        assert wait(lambda: srv.failed_handshakes >= 2) and "identity" not in seen
        assert KID in store._keys and KID not in store._reserved
        srv.close()


@needs
def test_a_classical_only_nss_client_cannot_downgrade_our_hybrid_server():
    with tempfile.TemporaryDirectory() as td:
        srv, store, seen = psk_server()                                      # grupo por defecto: solo el híbrido
        assert "gnip" not in nss_client(srv.port, nss_db(Path(td)), "x25519", psk_hex())
        assert wait(lambda: srv.failed_handshakes >= 1) and "identity" not in seen and KID in store._keys
        srv.close()


@needs
def test_with_our_default_sha384_suite_nss_cannot_complete_and_the_key_is_kept():
    with tempfile.TemporaryDirectory() as td:
        srv, store, seen = psk_server(suite=P.CIPHERSUITE)                   # AES-256-GCM-SHA384: la PSK de NSS es SHA-256
        assert "gnip" not in nss_client(srv.port, nss_db(Path(td)), "x25519mlkem768", psk_hex())
        assert wait(lambda: srv.failed_handshakes >= 1) and "identity" not in seen and KID in store._keys
        srv.close()


def nss_server(tmp: Path, groups: str):
    """selfserv con un certificado autofirmado para localhost; devuelve (proceso, puerto, PEM del certificado)."""
    db = nss_db(tmp, "sdb")
    seed = tmp / "seed"
    seed.write_bytes(os.urandom(64))
    subprocess.run([CERTUTIL, "-S", "-d", db, "-n", "srv", "-s", "CN=localhost", "--extSAN", "dns:localhost,ip:127.0.0.1", "-x", "-t", "CTu,Cu,Cu", "-v", "12",
                    "-g", "2048", "-Z", "SHA256", "-z", str(seed)], check=True, capture_output=True, timeout=120)
    pem = tmp / "srv.pem"
    pem.write_bytes(subprocess.run([CERTUTIL, "-L", "-d", db, "-n", "srv", "-a"], check=True, capture_output=True, timeout=60).stdout)
    for _ in range(4):
        port = free_port()
        proc = subprocess.Popen([SELFSERV, "-d", db, "-n", "srv", "-p", str(port), "-V", "tls1.3:tls1.3", "-I", groups], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        end = time.time() + 8
        while time.time() < end and proc.poll() is None:
            with socket.socket() as probe:
                if probe.connect_ex(("127.0.0.1", port)) == 0:
                    return proc, port, pem
            time.sleep(0.05)
        proc.kill()
        proc.wait(5)
    raise AssertionError("selfserv no llegó a escuchar tras cuatro intentos")


@needs
def test_our_certificate_client_completes_hybrid_tls13_with_an_nss_server():
    with tempfile.TemporaryDirectory() as td:
        proc, port, pem = nss_server(Path(td), "x25519mlkem768")
        try:
            s = tls13.connect(tls13.client_context(pem), "127.0.0.1", port, server_hostname="localhost", timeout=8)
            assert s.version() == "TLSv1.3"        # NSS solo ofrece X25519MLKEM768 y nuestro contexto solo lo acepta (Python no expone el grupo por conexión): haberlo completado prueba el híbrido
            s.sendall(b"GET / HTTP/1.0\r\n\r\n")
            assert s.recv(15) == b"HTTP/1.0 200 OK"
            s.close()
        finally:
            proc.kill()
            proc.wait(5)


@needs
def test_our_certificate_client_refuses_an_nss_server_that_only_offers_a_classical_group():
    with tempfile.TemporaryDirectory() as td:
        proc, port, pem = nss_server(Path(td), "x25519")
        try:
            with pytest.raises(Exception) as exc:                              # alerta de fallo de apretón: no hay grupo en común y NO se baja
                tls13.connect(tls13.client_context(pem), "127.0.0.1", port, server_hostname="localhost", timeout=8)
            assert "handshake failure" in str(exc.value).lower() or "alert" in str(exc.value).lower()
        finally:
            proc.kill()
            proc.wait(5)
