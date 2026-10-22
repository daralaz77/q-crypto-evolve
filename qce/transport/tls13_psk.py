"""TLS 1.3 ESTÁNDAR con PSK externa derivada de la clave QKD y grupo híbrido X25519MLKEM768 (opción A de docs/QKD_TLS_OPTIONS.md).

Por qué existe: el módulo `ssl` de Python 3.14 no expone las PSK de TLS 1.3. Este módulo habla con el `libssl` de OpenSSL (≥ 3.5) por `ctypes`
y registra los callbacks de PSK externa de OpenSSL (`SSL_CTX_set_psk_find_session_callback` / `..._use_session_callback`). Resultado: la clave QKD
entra en el CALENDARIO DE CLAVES de TLS 1.3 (RFC 8446 §4.2.11, modo `psk_dhe_ke`) junto con el intercambio híbrido, sin protocolo propio por encima.
La autenticación es por posesión de la PSK (no hay certificados): el servidor y el cliente se prueban mutuamente.

Qué es nuestro y debe revisarse: el PUENTE `ctypes` (tipos, tiempos de vida de los callbacks, gestión de memoria), la derivación de la PSK a partir de la clave
QKD (HKDF-SHA256, 32 bytes, con el identificador como contexto), la reserva/consumo/liberación de la clave y la atestación posterior al apretón.
Qué NO es nuestro: el protocolo (TLS 1.3 de OpenSSL), cuyo análisis formal público incluye PSK. ESTADO: puente NO REVISADO por terceros.

Falla CERRADO: sin `libssl` ≥ 3.5, sin el grupo híbrido, con versión, grupo o suite distintos de los esperados, sin que la PSK se haya usado, con clave fuera de rango,
desconocida, reservada o consumida, o fuera de plazo, no hay conexión. No depende de `OPENSSL_CONF` ni del orden de importación.
"""
from __future__ import annotations

import ctypes
import os
import select
import socket
import struct
import threading
import time
from typing import Callable

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ..core import openssl_ffi as ffi
from ..core.encoding import lp as _lp
from ..core.errors import AuthenticationFailure, MalformedMessage, PolicyViolation, QCEError

GROUP = "X25519MLKEM768"
CIPHERSUITE = "TLS_AES_256_GCM_SHA384"
CIPHER_ID = b"\x13\x02"          # TLS_AES_256_GCM_SHA384: su hash (SHA-384) es el de los binders de la PSK
GROUPS = ("X25519MLKEM768", "SecP384r1MLKEM1024", "X25519")   # X25519 SOLO para interoperar con pilas sin híbrido (p. ej. GnuTLS 3.8): no protege frente a un ordenador cuántico.
# SecP384r1MLKEM1024 (P-384 + ML-KEM-1024, parámetros de nivel CNSA 2.0) es opcional: hay que pedirlo; el valor por defecto sigue siendo X25519MLKEM768. NO se admite ML-KEM «puro» (sin componente clásico).
REPORTED_GROUP_NAME = {"X25519MLKEM768": "X25519MLKEM768", "SecP384r1MLKEM1024": "SecP384r1MLKEM1024", "X25519": "x25519"}   # cómo informa OpenSSL (SSL_get0_group_name) cada grupo permitido
SUITES = {"TLS_AES_256_GCM_SHA384": b"\x13\x02", "TLS_AES_128_GCM_SHA256": b"\x13\x01"}   # la segunda solo por interoperabilidad (la PSK de otras herramientas va ligada a SHA-256)
TLS13 = 0x0304
PSK_INFO = b"QCE/TLS13-PSK/1"
PSK_LEN = 32
IDENT_MAX = 128
QKD_KEY_MIN = 32
QKD_KEY_MAX = 1024
MAX_FRAME = 1 << 20
HANDSHAKE_TIMEOUT = 10.0

WANT_READ, WANT_WRITE = 2, 3


PskTransportUnavailable = ffi.OpenSslUnavailable      # mismo tipo: quien captura la excepción antigua sigue funcionando


vp, cp, sz, ci = ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_int
_CB_CLIENT = ctypes.CFUNCTYPE(ci, vp, vp, ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte)), ctypes.POINTER(sz), ctypes.POINTER(vp))
_CB_SERVER = ctypes.CFUNCTYPE(ci, vp, ctypes.POINTER(ctypes.c_ubyte), sz, ctypes.POINTER(vp))
_SIGS = [("TLS_server_method", vp, []), ("TLS_client_method", vp, []), ("SSL_CTX_new", vp, [vp]), ("SSL_CTX_free", None, [vp]), ("SSL_new", vp, [vp]),
         ("SSL_free", None, [vp]), ("SSL_CTX_ctrl", ctypes.c_long, [vp, ci, ctypes.c_long, vp]), ("SSL_CTX_set_ciphersuites", ci, [vp, cp]),
         ("SSL_CTX_set_num_tickets", ci, [vp, sz]), ("SSL_set_fd", ci, [vp, ci]), ("SSL_connect", ci, [vp]), ("SSL_accept", ci, [vp]),
         ("SSL_read", ci, [vp, vp, ci]), ("SSL_write", ci, [vp, vp, ci]), ("SSL_get_error", ci, [vp, ci]), ("SSL_shutdown", ci, [vp]),
         ("SSL_SESSION_new", vp, []), ("SSL_SESSION_set1_master_key", ci, [vp, vp, sz]), ("SSL_SESSION_set_cipher", ci, [vp, vp]),
         ("SSL_SESSION_set_protocol_version", ci, [vp, ci]), ("SSL_CIPHER_find", vp, [vp, vp]), ("SSL_get0_group_name", cp, [vp]),
         ("SSL_get_version", cp, [vp]), ("SSL_get_current_cipher", vp, [vp]), ("SSL_CIPHER_get_name", cp, [vp]), ("SSL_session_reused", ci, [vp]),
         ("SSL_CTX_set_psk_use_session_callback", None, [vp, _CB_CLIENT]), ("SSL_CTX_set_psk_find_session_callback", None, [vp, _CB_SERVER]),
         ("SSL_CTX_new_ex", vp, [vp, cp, vp]), ("SSL_CTX_up_ref", ci, [vp]), ("SSL_CTX_use_certificate_chain_file", ci, [vp, cp]),
         ("SSL_CTX_use_PrivateKey", ci, [vp, vp]), ("SSL_CTX_check_private_key", ci, [vp])]

_lib_cache: tuple | None = None
_lib_lock = threading.Lock()


def _load():
    """`(libssl, libcrypto)` ya con las firmas de este módulo; cachea y falla cerrado (la carga vive en `core.openssl_ffi`)."""
    global _lib_cache
    with _lib_lock:
        if _lib_cache is None:
            _lib_cache = ffi.load(_SIGS)
        return _lib_cache


_errors = ffi.errors


def prepare_psk(qkd_key: bytes, identity: bytes) -> bytes:
    """PSK de 32 bytes derivada de la clave QKD, con el identificador como contexto (separación de dominios; la PSK de TLS no se reutiliza para nada más)."""
    if not isinstance(qkd_key, (bytes, bytearray)) or not QKD_KEY_MIN <= len(qkd_key) <= QKD_KEY_MAX:
        raise PolicyViolation(f"la clave QKD debe tener entre {QKD_KEY_MIN} y {QKD_KEY_MAX} bytes")
    _check_identity(identity)
    return HKDF(algorithm=hashes.SHA256(), length=PSK_LEN, salt=None, info=PSK_INFO + _lp(bytes(identity))).derive(bytes(qkd_key))


def _check_identity(identity: bytes) -> None:
    if not isinstance(identity, (bytes, bytearray)) or not 1 <= len(identity) <= IDENT_MAX:
        raise MalformedMessage(f"el identificador de clave debe tener entre 1 y {IDENT_MAX} bytes")


class PskTlsConnection:
    """Conexión TLS 1.3 con PSK ya establecida y atestiguada. Mensajes con longitud de 4 bytes (como `tls13.send_frame`)."""

    def __init__(self, lib, sock, ssl_p, ctx_p, keep, identity: bytes) -> None:
        self._l, self._c = lib
        self._sock, self._ssl, self._ctx, self._keep, self.identity = sock, ssl_p, ctx_p, keep, bytes(identity)
        self._closed = False

    # ---- E/S dirigida por plazos ---------------------------------------------------------------------------------------
    def _io(self, op, timeout: float, what: str) -> int:
        deadline = time.monotonic() + timeout
        while True:
            self._c.ERR_clear_error()   # la cola de errores es POR HILO: un error viejo (p. ej. de otra conexión) haría que SSL_get_error mienta
            r = op()
            if r > 0:
                return r
            e = self._l.SSL_get_error(self._ssl, r)
            if e in (WANT_READ, WANT_WRITE):
                left = deadline - time.monotonic()
                if left <= 0:
                    raise TimeoutError(f"plazo agotado ({what})")
                rl, wl = ([self._sock], []) if e == WANT_READ else ([], [self._sock])
                select.select(rl, wl, [], left)
                continue
            detail = _errors(self._c)
            if e == 6:  # SSL_ERROR_ZERO_RETURN
                raise MalformedMessage("conexión cerrada por el par")
            raise AuthenticationFailure(f"{what} falló en TLS 1.3 ({detail or 'error ' + str(e)})")

    def _read_exact(self, n: int, timeout: float) -> bytes:
        out = bytearray()
        buf = ctypes.create_string_buffer(min(max(n, 1), 65536))
        deadline = time.monotonic() + timeout
        while len(out) < n:
            want = min(n - len(out), len(buf))
            got = self._io(lambda: self._l.SSL_read(self._ssl, buf, want), max(deadline - time.monotonic(), 0.001), "lectura")
            out += buf.raw[:got]
        return bytes(out)

    def _write_all(self, data: bytes, timeout: float) -> None:
        view = memoryview(data)
        deadline = time.monotonic() + timeout
        while len(view):
            chunk = bytes(view[:65536])
            buf = ctypes.create_string_buffer(chunk, len(chunk))
            sent = self._io(lambda: self._l.SSL_write(self._ssl, buf, len(chunk)), max(deadline - time.monotonic(), 0.001), "escritura")
            view = view[sent:]

    def send_frame(self, data: bytes, timeout: float = 30.0) -> None:
        if len(data) > MAX_FRAME:
            raise MalformedMessage("mensaje demasiado grande")
        self._write_all(struct.pack(">I", len(data)) + data, timeout)

    def recv_frame(self, max_size: int = MAX_FRAME, timeout: float = 30.0) -> bytes:
        (n,) = struct.unpack(">I", self._read_exact(4, timeout))
        if n > max_size:
            raise MalformedMessage("mensaje mayor que el máximo permitido")
        return self._read_exact(n, timeout)

    # ---- datos atestiguados ------------------------------------------------------------------------------------------------
    @property
    def group(self) -> str:
        return (self._l.SSL_get0_group_name(self._ssl) or b"").decode()

    @property
    def version(self) -> str:
        return (self._l.SSL_get_version(self._ssl) or b"").decode()

    @property
    def cipher(self) -> str:
        c = self._l.SSL_get_current_cipher(self._ssl)
        return (self._l.SSL_CIPHER_get_name(c) or b"").decode() if c else ""

    @property
    def psk_used(self) -> bool:
        return self._l.SSL_session_reused(self._ssl) == 1

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._l.SSL_shutdown(self._ssl)
        except Exception:  # noqa: BLE001
            pass
        self._c.ERR_clear_error()   # el cierre de una conexión no debe dejar errores a la siguiente del mismo hilo
        self._l.SSL_free(self._ssl)
        if self._ctx:
            self._l.SSL_CTX_free(self._ctx)
        try:
            self._sock.close()
        except OSError:
            pass
        self._keep.clear()


def _check_group(group: str) -> None:
    if group not in GROUPS:
        raise PolicyViolation(f"grupo no permitido: {group!r}")


def _check_suite(suite: str) -> bytes:
    if suite not in SUITES:
        raise PolicyViolation(f"suite no permitida: {suite!r}")
    return SUITES[suite]


def _new_ctx(lib, server: bool, suite: str, group: str = GROUP, libctx=None):
    l, _ = lib
    method = (l.TLS_server_method if server else l.TLS_client_method)()
    ctx = l.SSL_CTX_new_ex(libctx, None, method) if libctx else l.SSL_CTX_new(method)
    if not ctx:
        raise PskTransportUnavailable("no se pudo crear el contexto TLS")
    ok = l.SSL_CTX_ctrl(ctx, 123, TLS13, None) == 1 and l.SSL_CTX_ctrl(ctx, 124, TLS13, None) == 1   # mínimo y máximo = TLS 1.3
    groups = ctypes.create_string_buffer(group.encode())
    ok = ok and l.SSL_CTX_ctrl(ctx, 92, 0, ctypes.cast(groups, vp)) == 1                              # SSL_CTRL_SET_GROUPS_LIST: solo el híbrido
    ok = ok and l.SSL_CTX_set_ciphersuites(ctx, suite.encode()) == 1
    ok = ok and l.SSL_CTX_set_num_tickets(ctx, 0) == 1                                                    # sin reanudación
    if not ok:
        l.SSL_CTX_free(ctx)
        raise PskTransportUnavailable("OpenSSL rechazó la configuración TLS 1.3 / X25519MLKEM768")
    return ctx


def _session(lib, ssl_p, psk: bytes, suite: str):
    l, _ = lib
    s = l.SSL_SESSION_new()
    buf = ctypes.create_string_buffer(psk, len(psk))
    ok = s and l.SSL_SESSION_set1_master_key(s, ctypes.cast(buf, vp), len(psk)) == 1
    ctypes.memset(buf, 0, len(psk))
    cipher = l.SSL_CIPHER_find(ssl_p, SUITES[suite])
    ok = ok and cipher and l.SSL_SESSION_set_cipher(s, cipher) == 1 and l.SSL_SESSION_set_protocol_version(s, TLS13) == 1
    return s if ok else None


def _attest(conn: PskTlsConnection, suite: str, group: str = GROUP, require_psk: bool = True) -> None:
    """Tras el apretón se comprueba lo realmente negociado; cualquier discrepancia cierra la conexión (falla cerrado)."""
    problems = []
    if conn.version != "TLSv1.3":
        problems.append(f"versión {conn.version!r}")
    if conn.group != REPORTED_GROUP_NAME[group]:
        problems.append(f"grupo {conn.group!r}")
    if conn.cipher != suite:
        problems.append(f"suite {conn.cipher!r}")
    if require_psk and not conn.psk_used:
        problems.append("la PSK no se usó")
    if problems:
        conn.close()
        raise PolicyViolation("la conexión no cumple lo exigido: " + ", ".join(problems))


def _nodelay(sock: socket.socket) -> None:
    """Sin retraso de Nagle: el apretón intercambia mensajes pequeños en lockstep y, con ACK retardado, cada ida y vuelta costaba ≈ 40 ms en Linux (21 apretones/s frente a ≈ 600/s)."""
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except OSError:
        pass


def connect(sock: socket.socket, identity: bytes, qkd_key: bytes, timeout: float = HANDSHAKE_TIMEOUT, suite: str = CIPHERSUITE,
            group: str = GROUP) -> PskTlsConnection:
    """Cliente. `sock` ya está conectado por TCP. La clave QKD ya viene consumida de su broker (un solo uso)."""
    _check_suite(suite)
    _check_group(group)
    _nodelay(sock)
    psk = prepare_psk(qkd_key, identity)
    lib = _load()
    l, _ = lib
    ctx = _new_ctx(lib, False, suite, group)
    ident_buf = ctypes.create_string_buffer(bytes(identity), len(identity))

    def use(ssl_p, md, idp, idl, out):
        try:
            out[0] = _session(lib, ssl_p, psk, suite)
            idp[0] = ctypes.cast(ident_buf, ctypes.POINTER(ctypes.c_ubyte))
            idl[0] = len(identity)
            return 1 if out[0] else 0
        except Exception:  # noqa: BLE001  (una excepción no puede cruzar la frontera C)
            return 0
    cb = _CB_CLIENT(use)
    l.SSL_CTX_set_psk_use_session_callback(ctx, cb)
    ssl_p = l.SSL_new(ctx)
    sock.setblocking(False)
    l.SSL_set_fd(ssl_p, sock.fileno())
    conn = PskTlsConnection(lib, sock, ssl_p, ctx, [cb, ident_buf], identity)
    try:
        conn._io(lambda: l.SSL_connect(ssl_p), timeout, "apretón")
        _attest(conn, suite, group)
    except BaseException:
        conn.close()
        raise
    return conn


def accept(sock: socket.socket, source, timeout: float = HANDSHAKE_TIMEOUT, suite: str = CIPHERSUITE, group: str = GROUP) -> PskTlsConnection:
    """Servidor. `source` ofrece reserve/commit/release (qce.qkd.sources): la clave se reserva al ver el identificador, se consume solo si el apretón
    termina y se libera si falla o caduca. `conn.identity` es el identificador de la clave usada."""
    _check_suite(suite)
    _check_group(group)
    _nodelay(sock)
    lib = _load()
    l, _ = lib
    ctx = _new_ctx(lib, True, suite, group)
    state = {"id": None, "psk": None}

    def find(ssl_p, ident_p, idlen, out):
        try:
            out[0] = None
            ident = ctypes.string_at(ident_p, idlen)
            if not 1 <= len(ident) <= IDENT_MAX:
                return 1
            if state["id"] is None:
                key = source.reserve(ident)
                if key is None:
                    return 1
                try:
                    state["psk"] = prepare_psk(key, ident)
                except PolicyViolation:
                    source.commit(ident)   # material fuera de rango: inservible, se descarta
                    return 1
                state["id"] = ident
            if ident == state["id"]:
                out[0] = _session(lib, ssl_p, state["psk"], suite)
            return 1
        except Exception:  # noqa: BLE001
            return 0
    cb = _CB_SERVER(find)
    l.SSL_CTX_set_psk_find_session_callback(ctx, cb)
    ssl_p = l.SSL_new(ctx)
    sock.setblocking(False)
    l.SSL_set_fd(ssl_p, sock.fileno())
    conn = PskTlsConnection(lib, sock, ssl_p, ctx, [cb], b"")
    try:
        conn._io(lambda: l.SSL_accept(ssl_p), timeout, "apretón")
        conn.identity = state["id"] or b""
        _attest(conn, suite, group)
        if state["id"] is None:
            raise PolicyViolation("apretón completado sin clave reservada")
    except BaseException:
        if state["id"] is not None:
            source.release(state["id"])
        conn.close()
        raise
    source.commit(state["id"])
    return conn


class PskServer:
    """Servidor de laboratorio con un hilo por conexión: `handler(conn)` recibe la conexión ya atestiguada (el id de clave está en `conn.identity`)."""

    def __init__(self, source, handler: Callable[[PskTlsConnection], None], host: str = "127.0.0.1", port: int = 0, timeout: float = HANDSHAKE_TIMEOUT,
                 suite: str = CIPHERSUITE, group: str = GROUP) -> None:
        self._source, self._handler, self._timeout, self._suite, self._group = source, handler, timeout, suite, group
        self._ls = socket.socket()
        self._ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._ls.bind((host, port))
        self._ls.listen(16)
        self.port = self._ls.getsockname()[1]
        self.failed_handshakes = 0
        self._stop = False
        self._thread = threading.Thread(target=self._loop, daemon=True)

    def start(self) -> "PskServer":
        self._thread.start()
        return self

    def _loop(self) -> None:
        while not self._stop:
            try:
                raw, _ = self._ls.accept()
            except OSError:
                return
            threading.Thread(target=self._one, args=(raw,), daemon=True).start()

    def _one(self, raw: socket.socket) -> None:
        try:
            conn = accept(raw, self._source, self._timeout, self._suite, self._group)
        except (QCEError, OSError, TimeoutError):
            self.failed_handshakes += 1
            raw.close()
            return
        try:
            self._handler(conn)
        except (QCEError, OSError, TimeoutError):
            pass
        finally:
            conn.close()

    def close(self) -> None:
        self._stop = True
        self._ls.close()


def connect_tcp(host: str, port: int, identity: bytes, qkd_key: bytes, timeout: float = HANDSHAKE_TIMEOUT, suite: str = CIPHERSUITE,
                group: str = GROUP) -> PskTlsConnection:
    raw = socket.create_connection((host, port), timeout=timeout)
    try:
        return connect(raw, identity, qkd_key, timeout, suite, group)
    except BaseException:
        raw.close()
        raise
