"""Transporte TLS 1.3 con intercambio de claves HÍBRIDO obligatorio (X25519MLKEM768) y fallo cerrado.

Por qué existe: el apretón QCE1 es una composición propia sin revisión pública. TLS 1.3 con el grupo híbrido estándar
X25519MLKEM768 es la vía recomendada para producción (ADR-3). Este módulo no implementa criptografía: configura y verifica
la pila TLS del sistema (OpenSSL ≥ 3.5) para que NO pueda negociar nada clásico.

Limitación de Python 3.14 que condiciona el diseño: `ssl` no permite elegir grupos (`set_groups` llega más tarde) y no
informa del grupo negociado. Por eso:
  1. los grupos, la versión mínima y los conjuntos de cifrado se fijan con una configuración de OpenSSL (OPENSSL_CONF), y
  2. antes de crear cualquier contexto se ejecuta una ATESTACIÓN en bucle local que comprueba que un par que solo ofrece
     una curva clásica NO consigue conectar, que un cliente limitado a TLS 1.2 NO conecta y que el par por defecto SÍ conecta.
     Si la atestación falla se lanza TransportMisconfigured: no hay degradación silenciosa.
Un tercero puede confirmar el grupo con `openssl s_client` (ver tests/test_tls13_transport.py).
"""
from __future__ import annotations

import os
import socket
import ssl
import struct
import tempfile
import threading
from pathlib import Path

from ..core.errors import MalformedMessage, QCEError

HYBRID_GROUP = "X25519MLKEM768"
CIPHERSUITES = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256"
MAX_FRAME = 1 << 20
CLASSICAL_GROUPS = ("prime256v1", "secp384r1", "X25519", "X448")  # nombres que acepta SSLContext.set_ecdh_curve
OPENSSL_CNF = f"""openssl_conf = openssl_init
[openssl_init]
ssl_conf = ssl_sect
[ssl_sect]
system_default = system_default_sect
[system_default_sect]
MinProtocol = TLSv1.3
Groups = {HYBRID_GROUP}
Ciphersuites = {CIPHERSUITES}
"""


class TransportMisconfigured(QCEError):
    """La pila TLS del proceso no garantiza el grupo híbrido: no se abre ningún canal."""


_cnf_dir: tempfile.TemporaryDirectory | None = None  # se conserva vivo mientras viva el proceso
_attested = False
_lock = threading.Lock()


def config_path() -> Path:
    global _cnf_dir
    if _cnf_dir is None:
        _cnf_dir = tempfile.TemporaryDirectory(prefix="qce-tls-")
        os.chmod(_cnf_dir.name, 0o700)
    p = Path(_cnf_dir.name) / "openssl-hybrid.cnf"
    if not p.exists():
        p.write_text(OPENSSL_CNF)
        p.chmod(0o600)
    return p


def _export_config() -> None:
    """Fija OPENSSL_CONF si nadie lo fijó. Debe ocurrir ANTES de importar `cryptography` en el proceso: si no, la configuración
    no se aplica a `ssl` (medido en este equipo). La atestación lo detecta y el módulo falla cerrado."""
    if "OPENSSL_CONF" not in os.environ:
        os.environ["OPENSSL_CONF"] = str(config_path())


def child_env(base: dict | None = None) -> dict:
    """Entorno para procesos hijos (o para arrancar el servicio): fija OPENSSL_CONF antes de que OpenSSL se inicialice."""
    env = dict(os.environ if base is None else base)
    env["OPENSSL_CONF"] = str(config_path())
    return env


def _loopback(server_ctx: ssl.SSLContext, client_ctx: ssl.SSLContext) -> bool:
    ls = socket.socket()
    ls.settimeout(5)
    ls.bind(("127.0.0.1", 0))
    ls.listen(1)
    ok = {"s": False}

    def serve():
        try:
            conn, _ = ls.accept()
            conn.settimeout(5)
            ssl_conn = server_ctx.wrap_socket(conn, server_side=True)
            ok["s"] = ssl_conn.version() == "TLSv1.3"
            ssl_conn.close()
        except (OSError, ssl.SSLError):
            pass
    t = threading.Thread(target=serve, daemon=True)
    t.start()
    try:
        raw = socket.create_connection(("127.0.0.1", ls.getsockname()[1]), timeout=5)
        c = client_ctx.wrap_socket(raw, server_hostname="localhost")
        done = c.version() == "TLSv1.3"
        c.close()
    except (OSError, ssl.SSLError):
        done = False
    t.join(timeout=6)
    ls.close()
    return done and ok["s"]


def _attest() -> None:
    from . import pki  # PKI efímera solo para el autodiagnóstico
    with tempfile.TemporaryDirectory(prefix="qce-attest-") as d:
        os.chmod(d, 0o700)
        dp = Path(d)
        ca_path, ca_key, ca_cert = pki.issue_ca(dp)
        cert, key = pki.issue_leaf(dp, ca_key, ca_cert, "localhost", server=True)

        def server(**kw):
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(str(cert), str(key))
            if kw.get("curve"):
                ctx.set_ecdh_curve(kw["curve"])
            return ctx

        def client(**kw):
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.load_verify_locations(str(ca_path))
            if kw.get("curve"):
                ctx.set_ecdh_curve(kw["curve"])
            if kw.get("tls12"):
                ctx.maximum_version = ssl.TLSVersion.TLSv1_2
            return ctx

        checks = [("el par por defecto debe conectar por TLS 1.3", _loopback(server(), client()), True)]
        for curve in CLASSICAL_GROUPS:  # ninguna oferta solo-clásica puede conectar, en ningún sentido
            checks.append((f"un cliente que solo ofrece {curve} NO debe conectar", _loopback(server(), client(curve=curve)), False))
            checks.append((f"un servidor que solo ofrece {curve} NO debe aceptar al cliente por defecto", _loopback(server(curve=curve), client()), False))
        checks.append(("un cliente limitado a TLS 1.2 NO debe conectar", _loopback(server(), client(tls12=True)), False))
    bad = [msg for msg, got, want in checks if got != want]
    if bad:
        raise TransportMisconfigured(
            "la pila TLS de este proceso no garantiza el grupo híbrido (¿se importó `cryptography` o se creó un contexto SSL antes de fijar OPENSSL_CONF? Importe `qce.transport.tls13` lo primero). "
            "Arranque el proceso con el entorno de `child_env()`. Fallos: " + "; ".join(bad))


def require_hybrid_only() -> None:
    """Fija OPENSSL_CONF si aún es posible y atestigua el comportamiento. Resultado cacheado por proceso."""
    global _attested
    with _lock:
        if _attested:
            return
        _export_config()
        _attest()
        _attested = True


def server_context(certfile: str | Path, keyfile: str | Path, client_ca: str | Path | None = None,
                   key_password: bytes | None = None) -> ssl.SSLContext:
    """Servidor TLS 1.3 híbrido. Con `client_ca` exige certificado de cliente (autenticación mutua; QCE1 no la tiene)."""
    require_hybrid_only()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(str(certfile), str(keyfile), password=key_password)  # clave cifrada: la contraseña solo existe en memoria
    ctx.options |= ssl.OP_NO_COMPRESSION | ssl.OP_NO_TICKET
    ctx.num_tickets = 0  # sin reanudación de sesión: cada conexión hace un apretón completo y fresco
    if client_ca is not None:
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations(str(client_ca))
    return ctx


def client_context(ca_file: str | Path, client_cert: str | Path | None = None, client_key: str | Path | None = None) -> ssl.SSLContext:
    """Cliente TLS 1.3 híbrido: verifica cadena y nombre, y confía SOLO en `ca_file` (nunca en el almacén del sistema)."""
    require_hybrid_only()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)  # check_hostname=True y CERT_REQUIRED por defecto
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_verify_locations(str(ca_file))
    ctx.options |= ssl.OP_NO_COMPRESSION
    if client_cert is not None:
        ctx.load_cert_chain(str(client_cert), str(client_key))
    return ctx


# ---- mensajes con longitud (sin secretos en los errores) ---------------------------------------------------------------
def send_frame(sock: ssl.SSLSocket, data: bytes) -> None:
    if len(data) > MAX_FRAME:
        raise MalformedMessage("mensaje demasiado grande")
    sock.sendall(struct.pack(">I", len(data)) + data)


def _recv_exact(sock: ssl.SSLSocket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise MalformedMessage("conexión cerrada a mitad de un mensaje")
        buf += chunk
    return bytes(buf)


def recv_frame(sock: ssl.SSLSocket, max_size: int = MAX_FRAME) -> bytes:
    (n,) = struct.unpack(">I", _recv_exact(sock, 4))
    if n > max_size:
        raise MalformedMessage("mensaje mayor que el máximo permitido")
    return _recv_exact(sock, n)


class TlsServer:
    """Servidor de mensajes con hilo por conexión (laboratorio). `handler(conn, peer_cert)` recibe la conexión ya autenticada."""

    def __init__(self, ctx: ssl.SSLContext, handler, host: str = "127.0.0.1", port: int = 0) -> None:
        self._ctx, self._handler = ctx, handler
        self._ls = socket.socket()
        self._ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._ls.bind((host, port))
        self._ls.listen(16)
        self.port = self._ls.getsockname()[1]
        self.failed_handshakes = 0
        self._stop = False
        self._thread = threading.Thread(target=self._loop, daemon=True)

    def start(self) -> "TlsServer":
        self._thread.start()
        return self

    def _loop(self) -> None:
        while not self._stop:
            try:
                raw, _ = self._ls.accept()
            except OSError:
                return
            threading.Thread(target=self._one, args=(raw,), daemon=True).start()

    def set_context(self, ctx: ssl.SSLContext) -> None:
        """Las conexiones NUEVAS usarán este contexto (rotación de clave/certificado); las abiertas no se tocan."""
        self._ctx = ctx

    def stop_accepting(self) -> None:
        """Revocación: ninguna conexión nueva se atiende (las abiertas deben cerrarse por quien revoca)."""
        self._ctx = None

    def _one(self, raw: socket.socket) -> None:
        raw.settimeout(10)
        ctx = self._ctx
        if ctx is None:
            self.failed_handshakes += 1
            raw.close()
            return
        try:
            conn = ctx.wrap_socket(raw, server_side=True)
        except (ssl.SSLError, OSError):
            self.failed_handshakes += 1
            raw.close()
            return
        try:
            self._handler(conn, conn.getpeercert())
        except (QCEError, OSError, ssl.SSLError):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def close(self) -> None:
        self._stop = True
        self._ls.close()


def connect(ctx: ssl.SSLContext, host: str, port: int, server_hostname: str | None = None, timeout: float = 10) -> ssl.SSLSocket:
    raw = socket.create_connection((host, port), timeout=timeout)
    return ctx.wrap_socket(raw, server_hostname=server_hostname or host)


_export_config()  # al importar este módulo, primero que nada
