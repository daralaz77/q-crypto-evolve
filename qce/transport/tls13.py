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
import time
from pathlib import Path

from ..core.errors import MalformedMessage, QCEError
from ..core.ratelimit import ConnectionGuard

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
        p.write_text(OPENSSL_CNF, encoding="utf-8")
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


def _apply_crl(ctx: ssl.SSLContext, crl_file, ca_file: str | Path, min_crl_number: int | None, crl_pin=None) -> None:
    """Activa la revocación del certificado de la otra parte. Cada CRL se COMPRUEBA antes (firma, emisor, vigencia, número) y se falla cerrado.
    `crl_file` es una ruta (se comprueba solo la HOJA) o una lista/tupla de rutas (se comprueba la CADENA ENTERA: hace falta una CRL por cada CA que emite,
    firmada por esa CA, y todas ellas —la raíz y las intermedias— deben figurar en `ca_file`; falta una = se rechaza)."""
    if crl_file is None:
        if min_crl_number is not None or crl_pin is not None:
            raise TransportMisconfigured("min_crl_number/crl_pin sin crl_file: no hay lista que comprobar")
        return
    chain = not isinstance(crl_file, (str, os.PathLike))
    crls = list(crl_file) if chain else [crl_file]
    if not crls:
        raise TransportMisconfigured("la lista de CRL está vacía")
    if chain and min_crl_number is not None:
        raise TransportMisconfigured("min_crl_number vale para una sola CRL: con varias use crl_pin (un suelo por emisor)")
    from .crl import check_crl  # `cryptography` se importa aquí, ya fijado OPENSSL_CONF (require_hybrid_only se ejecutó antes)
    for one in crls:
        check_crl(one, ca_file, min_number=min_crl_number, pin=crl_pin)
        ctx.load_verify_locations(str(one))
    ctx.verify_flags |= ssl.VERIFY_CRL_CHECK_CHAIN if chain else ssl.VERIFY_CRL_CHECK_LEAF


def server_context(certfile: str | Path, keyfile: str | Path, client_ca: str | Path | None = None,
                   key_password: bytes | None = None, crl_file=None, min_crl_number: int | None = None, crl_pin=None) -> ssl.SSLContext:
    """Servidor TLS 1.3 híbrido. Con `client_ca` exige certificado de cliente (autenticación mutua; QCE1 no la tiene).
    Con `crl_file` (solo tiene sentido con `client_ca`) rechaza los clientes REVOCADOS; antes bastaba un certificado de cliente revocado para entrar."""
    require_hybrid_only()
    if (crl_file is not None or crl_pin is not None or min_crl_number is not None) and client_ca is None:
        raise TransportMisconfigured("crl_file/crl_pin/min_crl_number en el servidor exigen client_ca: sin autenticación mutua no hay certificado de cliente que revocar")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(str(certfile), str(keyfile), password=key_password)  # clave cifrada: la contraseña solo existe en memoria
    ctx.options |= ssl.OP_NO_COMPRESSION | ssl.OP_NO_TICKET
    ctx.num_tickets = 0  # sin reanudación de sesión: cada conexión hace un apretón completo y fresco
    if client_ca is not None:
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations(str(client_ca))
        _apply_crl(ctx, crl_file, client_ca, min_crl_number, crl_pin)
    return ctx


def client_context(ca_file: str | Path, client_cert: str | Path | None = None, client_key: str | Path | None = None,
                   crl_file=None, min_crl_number: int | None = None, crl_pin=None) -> ssl.SSLContext:
    """Cliente TLS 1.3 híbrido: verifica cadena y nombre, y confía SOLO en `ca_file` (nunca en el almacén del sistema).
    Con `crl_file` comprueba la revocación del certificado del servidor y FALLA CERRADO —al crear el contexto— si la lista falta, no la firmó la CA,
    caducó o su número es menor que `min_crl_number` (retroceso a una lista vieja)."""
    require_hybrid_only()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)  # check_hostname=True y CERT_REQUIRED por defecto
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_verify_locations(str(ca_file))
    _apply_crl(ctx, crl_file, ca_file, min_crl_number, crl_pin)
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


def _kill(conn: socket.socket) -> None:
    """Corta una conexión desde otro hilo (el que espera en `recv` recibe un error). Se usa la `shutdown` del socket base: la de `SSLSocket` anula `_sslobj`."""
    try:
        socket.socket.shutdown(conn, socket.SHUT_RDWR)
    except OSError:
        pass


class TlsServer:
    """Servidor de mensajes con hilo por conexión (laboratorio). `handler(conn, peer_cert)` recibe la conexión ya autenticada.

    Defensas contra agotamiento de recursos (T5; capa de aplicación, NO sustituyen a un cortafuegos):
      - `max_connections` y `max_per_origin`: tope de conexiones simultáneas (hilos), global y por origen. La que excede se cierra sin hilo ni criptografía
        (`rejected_busy` / `rejected_origin`). Sin el tope por origen, uno solo llenaba el global y dejaba fuera a todos.
      - `handshake_timeout`: plazo TOTAL del apretón TLS. Antes solo había plazo por operación (10 s), y quien enviaba un byte cada 9 s lo mantenía vivo para siempre.
      - `max_lifetime`: vida máxima de una conexión ya autenticada (None = sin tope).
      - el bucle de `accept` sobrevive a los errores transitorios (sin descriptores, conexión abortada): antes UNO terminaba el servidor en silencio."""

    def __init__(self, ctx: ssl.SSLContext, handler, host: str = "127.0.0.1", port: int = 0, limiter=None, *, max_connections: int = 256,
                 handshake_timeout: float = 10.0, max_lifetime: float | None = 300.0, max_per_origin: int | None = 32) -> None:
        if handshake_timeout <= 0 or (max_lifetime is not None and max_lifetime <= 0):
            raise ValueError("parámetros de límite inválidos")
        self._ctx: ssl.SSLContext | None = ctx
        self._handler = handler
        self._limiter = limiter  # OriginRateLimiter opcional: se aplica ANTES del apretón TLS (rechazo barato)
        self._guard = ConnectionGuard(max_connections, max_per_origin)   # ValueError si los topes no son positivos
        self._handshake_timeout, self._max_lifetime = handshake_timeout, max_lifetime
        self._count_lock = threading.Lock()
        self.rate_limited = 0
        self.rejected_busy = 0
        self.rejected_origin = 0
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

    def _bump(self, counter: str) -> None:
        with self._count_lock:
            setattr(self, counter, getattr(self, counter) + 1)

    def _loop(self) -> None:
        while not self._stop:
            try:
                raw, addr = self._ls.accept()
            except OSError:
                if self._stop or self._ls.fileno() == -1:
                    return  # se cerró el servidor
                time.sleep(0.05)  # error transitorio (EMFILE, ECONNABORTED…): se sigue atendiendo, sin girar en vacío
                continue
            if self._limiter is not None and not self._limiter.allow(str(addr[0])):
                self._bump("rate_limited")
                raw.close()  # sin hilo, sin apretón TLS, sin criptografía
                continue
            origin = str(addr[0])
            refused = self._guard.acquire(origin)
            if refused is not None:
                self._bump("rejected_busy" if refused == "busy" else "rejected_origin")
                raw.close()
                continue
            try:
                threading.Thread(target=self._one, args=(raw, origin), daemon=True).start()
            except RuntimeError:  # el sistema no da más hilos (`can't start new thread`): se libera el hueco y se cierra
                self._guard.release(origin)
                raw.close()

    def set_context(self, ctx: ssl.SSLContext) -> None:
        """Las conexiones NUEVAS usarán este contexto (rotación de clave/certificado); las abiertas no se tocan."""
        self._ctx = ctx

    def stop_accepting(self) -> None:
        """Revocación: ninguna conexión nueva se atiende (las abiertas deben cerrarse por quien revoca)."""
        self._ctx = None

    def _one(self, raw: socket.socket, origin: str) -> None:
        try:
            self._serve(raw)
        finally:
            self._guard.release(origin)

    def _serve(self, raw: socket.socket) -> None:
        raw.settimeout(10)
        ctx = self._ctx
        if ctx is None:
            self._bump("failed_handshakes")
            raw.close()
            return
        try:
            conn = ctx.wrap_socket(raw, server_side=True, do_handshake_on_connect=False)
        except (ssl.SSLError, OSError):
            self._bump("failed_handshakes")
            raw.close()
            return
        deadline = threading.Timer(self._handshake_timeout, _kill, args=(conn,))
        deadline.daemon = True
        deadline.start()
        try:
            conn.do_handshake()
        except (ssl.SSLError, OSError):
            self._bump("failed_handshakes")
            conn.close()
            return
        finally:
            deadline.cancel()
        life = None
        if self._max_lifetime is not None:
            life = threading.Timer(self._max_lifetime, _kill, args=(conn,))
            life.daemon = True
            life.start()
        try:
            self._handler(conn, conn.getpeercert())
        except (QCEError, OSError, ssl.SSLError):
            pass
        finally:
            if life is not None:
                life.cancel()
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
