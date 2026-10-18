"""QIL1: capa interna con clave QKD sobre TLS 1.3, ligada a la sesión TLS. ESTADO: NO REVISADA por terceros (composición propia).

Especificación: docs/QKD_LAYER_SPEC.md. Modelo formal: formal/qil1.spthy. Por qué existe: ninguna pila TLS disponible aquí admite una PSK
externa en TLS 1.3, así que la clave QKD no puede entrar en el calendario de claves de TLS; en su lugar se aplica DENTRO del canal TLS,
con una derivación ligada a esa sesión (valor `tls-unique` + huella del certificado del servidor). Resultado: una cascada de dos cifrados
independientes, no un combinador dentro de TLS. Si un atacante termina TLS con un certificado falso, la derivación lo detecta.

Falla CERRADO: sin TLS 1.3, sin valor de ligadura, con clave QKD corta, desconocida o ya consumida, o con una etiqueta incorrecta,
no hay capa. Al servidor que rechaza no se le pide que explique nada al par: cierra (sin oráculo de errores).
"""
from __future__ import annotations

from . import tls13  # PRIMERO de todo: fija OPENSSL_CONF antes de importar nada que inicialice OpenSSL (ver qce/transport/custody.py)
import hashlib  # noqa: E402
import hmac  # noqa: E402
import os  # noqa: E402
import threading  # noqa: E402
from typing import Callable  # noqa: E402

from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305  # noqa: E402
from cryptography.hazmat.primitives.kdf.hkdf import HKDF  # noqa: E402

from ..core.errors import AuthenticationFailure, KeyStateError, MalformedMessage, PolicyViolation  # noqa: E402

VERSION = b"QIL1"
TH_LABEL = b"QIL1/th"
INFO_CONF, INFO_C2S, INFO_S2C = b"QIL1/conf", b"QIL1/c2s", b"QIL1/s2c"
REC_AAD_LABEL = b"QIL1/rec"
ROLE_CLIENT, ROLE_SERVER = b"client", b"server"
NONCE_LEN = 32
TAG_LEN = 32
KEY_ID_MAX = 128
QKD_KEY_MIN = 32            # 256 bits: por debajo no hay capa (el material QKD que se acepta es de sesión, no una contraseña)
QKD_KEY_MAX = 1024
BIND_MIN = 12               # tls-unique de TLS 1.3 en OpenSSL mide 48 bytes; menos de 12 no es un valor de ligadura creíble
MAX_RECORDS = 1 << 32       # límite de registros por dirección (el contador es el nonce); más allá hay que abrir otra sesión
MAX_PLAINTEXT = tls13.MAX_FRAME - 16
HANDSHAKE_TIMEOUT = 10.0   # segundos que el servidor mantiene una clave reservada esperando al cliente


def _lp(x: bytes) -> bytes:
    return len(x).to_bytes(4, "big") + x


def _mac(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()


def cert_fingerprint(cert_der: bytes) -> bytes:
    return hashlib.sha256(cert_der).digest()


def transcript_hash(bind: bytes, cert_fp: bytes, key_id: bytes, nc: bytes, ns: bytes) -> bytes:
    return hashlib.sha256(_lp(TH_LABEL) + _lp(bind) + _lp(cert_fp) + _lp(key_id) + _lp(nc) + _lp(ns)).digest()


def _expand(qkd_key: bytes, th: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=th, info=info).derive(qkd_key)


def _binding(sock) -> bytes:
    """Valor de ligadura de la sesión TLS 1.3 actual. Sin él no hay capa: la ligadura es lo que frena la retransmisión."""
    if sock.version() != "TLSv1.3":
        raise PolicyViolation("la capa QKD exige TLS 1.3")
    bind = sock.get_channel_binding("tls-unique")
    if not bind or len(bind) < BIND_MIN:
        raise PolicyViolation("la pila TLS no ofrece un valor de ligadura utilizable")
    return bind


def _check_key(qkd_key: bytes) -> None:
    if not isinstance(qkd_key, (bytes, bytearray)) or not QKD_KEY_MIN <= len(qkd_key) <= QKD_KEY_MAX:
        raise PolicyViolation(f"la clave QKD debe tener entre {QKD_KEY_MIN} y {QKD_KEY_MAX} bytes")


def _check_key_id(key_id: bytes) -> None:
    if not isinstance(key_id, (bytes, bytearray)) or not 1 <= len(key_id) <= KEY_ID_MAX:
        raise MalformedMessage(f"el identificador de clave debe tener entre 1 y {KEY_ID_MAX} bytes")


def encode_hello(key_id: bytes, nc: bytes) -> bytes:
    return VERSION + bytes([len(key_id)]) + key_id + nc


def decode_hello(data: bytes) -> tuple[bytes, bytes]:
    if len(data) < len(VERSION) + 1 or data[:4] != VERSION:
        raise MalformedMessage("HELLO de QIL1 con versión o forma inválida")
    n = data[4]
    if not 1 <= n <= KEY_ID_MAX or len(data) != 5 + n + NONCE_LEN:
        raise MalformedMessage("HELLO de QIL1 con longitud inválida")
    return data[5:5 + n], data[5 + n:]


class Layer:
    """Capa de registros: ChaCha20-Poly1305, una clave por dirección, nonce = contador de 96 bits, AAD = etiqueta + th."""

    def __init__(self, sock, send_key: bytes, recv_key: bytes, th: bytes) -> None:
        self._sock, self._th = sock, th
        self._send, self._recv = ChaCha20Poly1305(send_key), ChaCha20Poly1305(recv_key)
        self._n_out = self._n_in = 0

    def _aad(self) -> bytes:
        return REC_AAD_LABEL + self._th

    def write(self, data: bytes) -> None:
        if len(data) > MAX_PLAINTEXT:
            raise MalformedMessage("mensaje demasiado grande para un registro")
        if self._n_out >= MAX_RECORDS:
            raise KeyStateError("se agotó el contador de registros: abra otra sesión")
        ct = self._send.encrypt(self._n_out.to_bytes(12, "big"), data, self._aad())
        self._n_out += 1
        tls13.send_frame(self._sock, ct)

    def read(self) -> bytes:
        if self._n_in >= MAX_RECORDS:
            raise KeyStateError("se agotó el contador de registros: abra otra sesión")
        ct = tls13.recv_frame(self._sock)
        try:
            pt = self._recv.decrypt(self._n_in.to_bytes(12, "big"), ct, self._aad())
        except Exception as exc:  # InvalidTag: manipulado, repetido, reordenado o de otra sesión
            raise AuthenticationFailure("registro de la capa QKD no autentica") from exc
        self._n_in += 1
        return pt

    @property
    def transcript_hash(self) -> bytes:
        return self._th


def client_layer(sock, key_id: bytes, qkd_key: bytes, rng: Callable[[int], bytes] = os.urandom) -> Layer:
    """Cliente: envía HELLO, verifica la etiqueta del servidor, responde con la suya. `qkd_key` ya viene consumida del broker (un solo uso)."""
    _check_key_id(key_id)
    _check_key(qkd_key)
    bind = _binding(sock)
    cert = sock.getpeercert(binary_form=True)
    if not cert:
        raise PolicyViolation("no hay certificado del servidor al que ligar la capa")
    fp = cert_fingerprint(cert)
    nc = rng(NONCE_LEN)
    tls13.send_frame(sock, encode_hello(key_id, nc))
    accept = tls13.recv_frame(sock)
    if len(accept) != NONCE_LEN + TAG_LEN:
        raise MalformedMessage("ACCEPT de QIL1 con longitud inválida")
    ns, ts = accept[:NONCE_LEN], accept[NONCE_LEN:]
    th = transcript_hash(bind, fp, key_id, nc, ns)
    conf = _expand(qkd_key, th, INFO_CONF)
    if not hmac.compare_digest(ts, _mac(conf, ROLE_SERVER + th)):
        raise AuthenticationFailure("el servidor no demostró conocer la clave QKD ligada a esta sesión TLS")
    tls13.send_frame(sock, _mac(conf, ROLE_CLIENT + th + ts))
    return Layer(sock, _expand(qkd_key, th, INFO_C2S), _expand(qkd_key, th, INFO_S2C), th)


def server_layer(sock, source, server_cert_der: bytes, rng: Callable[[int], bytes] = os.urandom) -> Layer:
    """Servidor. `source` ofrece `reserve(kid) -> clave | None`, `commit(kid)` y `release(kid)`: la clave se RESERVA al recibir un HELLO bien
    formado, se CONSUME solo si el cliente demuestra poseerla, y se LIBERA si el apretón falla o caduca (`HANDSHAKE_TIMEOUT`). Así quien solo
    conoce el identificador no puede gastar la clave (T43); el consumo único se mantiene para todo apretón completado (modelo: `key_single_use`)."""
    bind = _binding(sock)
    fp = cert_fingerprint(server_cert_der)
    previous = sock.gettimeout()
    sock.settimeout(HANDSHAKE_TIMEOUT)
    try:
        key_id, nc = decode_hello(tls13.recv_frame(sock))
        qkd_key = source.reserve(key_id)
        if qkd_key is None:
            raise AuthenticationFailure("clave QKD desconocida, reservada o ya consumida")
        try:
            _check_key(qkd_key)
        except PolicyViolation:
            source.commit(key_id)  # material fuera de rango: inservible, se descarta
            raise
        try:
            ns = rng(NONCE_LEN)
            th = transcript_hash(bind, fp, key_id, nc, ns)
            conf = _expand(qkd_key, th, INFO_CONF)
            ts = _mac(conf, ROLE_SERVER + th)
            tls13.send_frame(sock, ns + ts)
            tc = tls13.recv_frame(sock)
            if not hmac.compare_digest(tc, _mac(conf, ROLE_CLIENT + th + ts)):
                raise AuthenticationFailure("el cliente no demostró conocer la clave QKD ligada a esta sesión TLS")
        except BaseException:
            source.release(key_id)
            raise
        source.commit(key_id)
        layer = Layer(sock, _expand(qkd_key, th, INFO_S2C), _expand(qkd_key, th, INFO_C2S), th)
    finally:
        sock.settimeout(previous)
    return layer


from ..qkd.sources import BrokerSource, OneTimeKeys  # noqa: E402,F401  (se reexportan: la capa QIL1 los usa por este nombre)
