"""Interoperabilidad con una SEGUNDA implementación independiente que SÍ trae el híbrido: Mozilla NSS (código distinto de OpenSSL y de GnuTLS).

Qué contrasta con NSS (las herramientas `tstclnt` y `selfserv` de NSS ≥ 3.125):
  · el grupo híbrido X25519MLKEM768 con PSK externa: cliente NSS contra nuestro servidor PSK, y rechazo con PSK o identidad equivocadas;
  · que no hay bajada silenciosa: un cliente NSS que solo ofrece X25519 no completa el apretón con nuestro servidor híbrido;
  · el híbrido con certificados en el otro sentido: nuestro cliente TLS contra `selfserv` de NSS, y la negativa a usar un NSS que solo ofrece X25519.
La ruta con la clave en el HSM está en `tests/test_hsm_tls.py` (escenario `nss`).

  · el SENTIDO CONTRARIO de la PSK (nuestro cliente PSK contra un servidor NSS) con un servidor mínimo escrito sobre la biblioteca NSS (`tests/helpers/nss_psk_server.c`, se compila al vuelo):
    `selfserv` NO sirve para eso porque no aplica la PSK externa en el servidor (autentica por certificado aunque se le dé una PSK, incluso frente a `tstclnt`; se probó con
    varias variantes). El ayudante añade la PSK al socket ACEPTADO y NSS informa de que autenticó por PSK (`ssl_auth_psk`), no por certificado.

LÍMITES, medidos y no supuestos:
  · el ayudante necesita un certificado configurado (NSS no ofrece suites TLS 1.3 sin él); lo que se comprueba es que NSS ELIGE la PSK;
  · la PSK externa de NSS va ligada a SHA-256, como la de OpenSSL y GnuTLS: con nuestra suite por defecto (AES-256-GCM-SHA384) NSS no completa el apretón (se prueba).
"""
import atexit
import json
import os
import shutil
import socket
import subprocess
import sys
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


ROOT = Path(__file__).resolve().parent.parent
CERT_CLIENT = """
import json, sys
from qce.transport import tls13
pem, port = sys.argv[1], int(sys.argv[2])
try:
    s = tls13.connect(tls13.client_context(pem), "localhost", port, server_hostname="localhost", timeout=8)  # "localhost": selfserv escucha en la familia que resuelva (INC-0035)
    s.sendall(b"GET / HTTP/1.0\\r\\n\\r\\n")
    print(json.dumps({"ok": True, "version": s.version(), "data": s.recv(15).decode()}))
except Exception as exc:
    print(json.dumps({"ok": False, "err": type(exc).__name__ + ": " + str(exc)[:200]}))
"""


def cert_client(pem, port):
    """El cliente con certificados exige un proceso arrancado con el entorno de `child_env()` (OPENSSL_CONF fijado antes de iniciar OpenSSL): va en un subproceso, como el resto de pruebas del transporte."""
    env = tls13.child_env({"PATH": "/usr/bin:/bin", "PYTHONPATH": str(ROOT)})
    r = subprocess.run([sys.executable, "-c", CERT_CLIENT, str(pem), str(port)], capture_output=True, text=True, timeout=60, env=env, cwd=ROOT)
    assert r.returncode == 0, r.stderr[-600:]
    return json.loads(r.stdout.strip().splitlines()[-1])


HELPER_SRC = Path(__file__).resolve().parent / "helpers" / "nss_psk_server.c"
_helper_cache: dict = {}


def nss_flags():
    """Banderas de compilación contra NSS/NSPR: pkg-config si existe, y si no las rutas de Homebrew (la mutación corre con un PATH mínimo)."""
    pc = shutil.which("pkg-config")
    if pc:
        r = subprocess.run([pc, "--cflags", "--libs", "nss", "nspr"], capture_output=True, text=True)
        if r.returncode == 0:
            return r.stdout.split()
    for nss, nspr in (("/opt/homebrew/opt/nss", "/opt/homebrew/opt/nspr"), ("/usr/local/opt/nss", "/usr/local/opt/nspr")):
        if os.path.exists(f"{nss}/include/nss/ssl.h") and os.path.exists(f"{nspr}/include/nspr/nspr.h"):
            return [f"-I{nss}/include/nss", f"-I{nspr}/include/nspr", f"-L{nss}/lib", f"-L{nspr}/lib", "-lssl3", "-lnss3", "-lnssutil3", "-lnspr4", f"-Wl,-rpath,{nss}/lib", f"-Wl,-rpath,{nspr}/lib"]
    return None


def helper_binary():
    """Compila una vez el servidor mínimo sobre NSS; None si no hay compilador o cabeceras de NSS."""
    if "bin" not in _helper_cache:
        cc, flags, out = shutil.which("cc") or "/usr/bin/cc", nss_flags(), None
        if flags and os.path.exists(cc) and HELPER_SRC.exists():
            d = tempfile.mkdtemp(prefix="qce-nss-")
            atexit.register(shutil.rmtree, d, True)
            r = subprocess.run([cc, "-O1", "-o", f"{d}/nss_psk_server", str(HELPER_SRC), *flags], capture_output=True, text=True, timeout=120)
            out = f"{d}/nss_psk_server" if r.returncode == 0 else None
        _helper_cache["bin"] = out
    return _helper_cache["bin"]


def start_nss_psk_server(tmp: Path, mode: str, psk=None, label=KID.decode()):
    """Devuelve (proceso, puerto). `mode`: hibrido | x25519 (el único grupo que ofrece el servidor NSS)."""
    binary = helper_binary()
    if not binary:
        pytest.skip("sin compilador o sin cabeceras de NSS para el servidor de prueba")
    db = nss_db(tmp, "psrv")
    seed = tmp / "pseed"
    seed.write_bytes(os.urandom(64))
    subprocess.run([CERTUTIL, "-S", "-d", db, "-n", "srv", "-s", "CN=localhost", "-x", "-t", "CTu,Cu,Cu", "-v", "12", "-g", "2048", "-Z", "SHA256", "-z", str(seed)],
                   check=True, capture_output=True, timeout=120)
    port = free_port()
    proc = subprocess.Popen([binary, str(port), psk or psk_hex(), label, mode, "1", db, "srv"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    assert proc.stdout.readline().strip() == "READY"
    return proc, port


def finish(proc):
    try:
        out, _ = proc.communicate(timeout=20)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, _ = proc.communicate()
    lines = [ln for ln in out.splitlines() if ln.startswith("{")]
    return json.loads(lines[-1]) if lines else None


@needs
def test_our_psk_client_completes_the_hybrid_handshake_with_an_nss_server_that_authenticates_by_psk():
    with tempfile.TemporaryDirectory() as td:
        proc, port = start_nss_psk_server(Path(td), "hibrido")
        c = P.connect_tcp("127.0.0.1", port, KID, KEY, timeout=8, suite=SUITE)         # grupo por defecto: el híbrido
        assert (c.version, c.group, c.cipher) == ("TLSv1.3", "X25519MLKEM768", SUITE)
        c._write_all(b"ping", 5)
        assert c._read_exact(4, 5) == b"gnip"
        c.close()
        seen = finish(proc)                                                              # lo que informa NSS, la OTRA implementación
        assert seen == {"ok": True, "version": 0x0304, "group": 4588, "suite": 0x1301, "auth": 9, "kea": 8, "read": 4}   # TLS 1.3, mlkem768x25519, AES-128-GCM-SHA256, autenticación por PSK


@needs
def test_nss_server_rejects_our_client_with_a_wrong_psk_or_identity():
    for kind in ("clave", "identidad"):
        with tempfile.TemporaryDirectory() as td:
            proc, port = start_nss_psk_server(Path(td), "hibrido")
            key, kid = (bytes(32), KID) if kind == "clave" else (KEY, b"otro-id")
            with pytest.raises((AuthenticationFailure, MalformedMessage, PolicyViolation)):
                P.connect_tcp("127.0.0.1", port, kid, key, timeout=8, suite=SUITE)
            seen = finish(proc)
            assert seen is None or seen["ok"] is False or seen["auth"] != 9, (kind, seen)   # nunca una sesión autenticada por PSK


@needs
def test_our_default_hybrid_client_does_not_downgrade_to_a_classical_group_with_an_nss_server():
    with tempfile.TemporaryDirectory() as td:
        proc, port = start_nss_psk_server(Path(td), "x25519")                           # NSS solo ofrece X25519
        with pytest.raises((AuthenticationFailure, MalformedMessage, PolicyViolation)):
            P.connect_tcp("127.0.0.1", port, KID, KEY, timeout=8, suite=SUITE)
        seen = finish(proc)
        assert seen is None or seen["ok"] is False                                       # y NSS no llegó a completar una sesión


@needs
def test_our_psk_client_interoperates_with_nss_in_the_classical_group_only_when_asked_explicitly():
    with tempfile.TemporaryDirectory() as td:
        proc, port = start_nss_psk_server(Path(td), "x25519")
        c = P.connect_tcp("127.0.0.1", port, KID, KEY, timeout=8, suite=SUITE, group="X25519")
        assert (c.version, c.group) == ("TLSv1.3", "x25519")                           # sin protección poscuántica: solo para interoperar
        c._write_all(b"ping", 5)
        assert c._read_exact(4, 5) == b"gnip"
        c.close()
        assert finish(proc)["auth"] == 9


@needs
def test_with_our_default_sha384_suite_nss_psk_server_cannot_complete():
    with tempfile.TemporaryDirectory() as td:
        proc, port = start_nss_psk_server(Path(td), "hibrido")
        with pytest.raises((AuthenticationFailure, MalformedMessage, PolicyViolation)):
            P.connect_tcp("127.0.0.1", port, KID, KEY, timeout=8, suite=P.CIPHERSUITE)    # AES-256-GCM-SHA384: la PSK de NSS es SHA-256
        seen = finish(proc)
        assert seen is None or seen["ok"] is False or seen["auth"] != 9


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
            try:
                socket.create_connection(("localhost", port), timeout=0.5).close()     # IPv4 o IPv6, la que resuelva localhost (INC-0035)
                return proc, port, pem
            except OSError:
                pass
            time.sleep(0.05)
        proc.kill()
        proc.wait(5)
    raise AssertionError("selfserv no llegó a escuchar tras cuatro intentos")


@needs
def test_our_certificate_client_completes_hybrid_tls13_with_an_nss_server():
    with tempfile.TemporaryDirectory() as td:
        proc, port, pem = nss_server(Path(td), "x25519mlkem768")
        try:
            r = cert_client(pem, port)
            # NSS solo ofrece X25519MLKEM768 y nuestro contexto solo lo acepta (Python no expone el grupo por conexión): haberlo completado prueba el híbrido
            assert r == {"ok": True, "version": "TLSv1.3", "data": "HTTP/1.0 200 OK"}
        finally:
            proc.kill()
            proc.wait(5)


@needs
def test_our_certificate_client_refuses_an_nss_server_that_only_offers_a_classical_group():
    with tempfile.TemporaryDirectory() as td:
        proc, port, pem = nss_server(Path(td), "x25519")
        try:
            r = cert_client(pem, port)                                         # alerta de fallo de apretón: no hay grupo en común y NO se baja
            assert r["ok"] is False and "handshake failure" in r["err"].lower()
        finally:
            proc.kill()
            proc.wait(5)


# ---- grupo de nivel alto (SecP384r1MLKEM1024 = secp384r1mlkem1024 en NSS) ---------------------------------------------------------------------------
HIGH_GROUP = "SecP384r1MLKEM1024"


@needs
def test_nss_client_completes_the_high_level_hybrid_group_with_our_psk_server():
    with tempfile.TemporaryDirectory() as td:
        srv, store, seen = psk_server(group=HIGH_GROUP)
        out = nss_client(srv.port, nss_db(Path(td)), "secp384r1mlkem1024", psk_hex())
        assert wait(lambda: "identity" in seen)
        assert (seen["identity"], seen["group"], seen["cipher"], seen["version"]) == (KID, HIGH_GROUP, SUITE, "TLSv1.3")
        assert "gnip" in out and wait(lambda: KID not in store._keys)
        srv.close()


@needs
def test_our_psk_client_completes_the_high_level_hybrid_group_with_an_nss_server_that_authenticates_by_psk():
    with tempfile.TemporaryDirectory() as td:
        proc, port = start_nss_psk_server(Path(td), "hibrido1024")
        c = P.connect_tcp("127.0.0.1", port, KID, KEY, timeout=8, suite=SUITE, group=HIGH_GROUP)
        assert (c.version, c.group, c.cipher) == ("TLSv1.3", HIGH_GROUP, SUITE)
        c._write_all(b"ping", 5)
        assert c._read_exact(4, 5) == b"gnip"
        c.close()
        assert finish(proc) == {"ok": True, "version": 0x0304, "group": 4589, "suite": 0x1301, "auth": 9, "kea": 8, "read": 4}   # 4589 = secp384r1mlkem1024 en NSS

