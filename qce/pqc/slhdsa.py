"""SLH-DSA-SHA2-128s (FIPS 205, firma basada en funciones hash) mediante el `libcrypto` de OpenSSL ≥ 3.5, por `ctypes`.

Por qué así: la biblioteca `cryptography` instalada (50.0.2) no incluye SLH-DSA, y reimplementar un algoritmo estandarizado a mano está prohibido por el
proyecto (sin criptografía propia). OpenSSL 3.6 sí lo trae; aquí solo hay un PUENTE de FFI (tipos C, `OSSL_PARAM`, ciclo de vida de `EVP_PKEY`/`EVP_MD_CTX`), NO REVISADO.

Papel: alternativa de firma de seguridad basada solo en hashes (sin supuestos de retículos ni curvas), de uso poco frecuente por el tamaño (firma de 7856 bytes) y la lentitud.
No está integrada en el apretón QCE1 (eso cambiaría el protocolo); se ofrece como primitiva para raíces de confianza y declaraciones de larga vida.
Las firmas son aleatorizadas por defecto (`deterministic=False`). Falla cerrado: sin OpenSSL ≥ 3.5 con el algoritmo, no hay primitiva.
"""
from __future__ import annotations

import ctypes
import threading

from ..core.errors import AuthenticationFailure, MalformedMessage, PolicyViolation
from ..transport import tls13_psk as _ffi

ALGORITHM = "SLH-DSA-SHA2-128s"
PK_LEN = 32
SK_LEN = 64
SIG_LEN = 7856
CONTEXT_MAX = 255

vp, cp, sz, ci = ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_int
OSSL_PARAM_INTEGER, OSSL_PARAM_OCTET_STRING = 1, 5
EVP_PKEY_PUBLIC_KEY, EVP_PKEY_KEYPAIR = 0x86, 0x87    # EVP_PKEY_KEY_PARAMETERS|... : selecciones de OpenSSL (OSSL_KEYMGMT_SELECT_*)


class OSSL_PARAM(ctypes.Structure):
    _fields_ = [("key", cp), ("data_type", ci), ("data", vp), ("data_size", sz), ("return_size", sz)]


_SIGS = [("EVP_PKEY_CTX_new_from_name", vp, [vp, cp, cp]), ("EVP_PKEY_CTX_free", None, [vp]), ("EVP_PKEY_keygen_init", ci, [vp]),
         ("EVP_PKEY_keygen", ci, [vp, ctypes.POINTER(vp)]), ("EVP_PKEY_free", None, [vp]),
         ("EVP_PKEY_get_octet_string_param", ci, [vp, cp, vp, sz, ctypes.POINTER(sz)]),
         ("EVP_PKEY_fromdata_init", ci, [vp]), ("EVP_PKEY_fromdata", ci, [vp, ctypes.POINTER(vp), ci, ctypes.POINTER(OSSL_PARAM)]),
         ("EVP_MD_CTX_new", vp, []), ("EVP_MD_CTX_free", None, [vp]),
         ("EVP_DigestSignInit_ex", ci, [vp, vp, cp, vp, cp, vp, ctypes.POINTER(OSSL_PARAM)]),
         ("EVP_DigestSign", ci, [vp, vp, ctypes.POINTER(sz), vp, sz]),
         ("EVP_DigestVerifyInit_ex", ci, [vp, vp, cp, vp, cp, vp, ctypes.POINTER(OSSL_PARAM)]),
         ("EVP_DigestVerify", ci, [vp, vp, sz, vp, sz])]
_cache = None
_lock = threading.Lock()


def _crypto():
    global _cache
    with _lock:
        if _cache is not None:
            return _cache
        try:
            crypto = _ffi._load()[1]
        except _ffi.PskTransportUnavailable as exc:
            raise PolicyViolation(f"SLH-DSA no disponible: {exc}") from exc
        for name, res, args in _SIGS:
            f = getattr(crypto, name)
            f.restype, f.argtypes = res, args
        ctx = crypto.EVP_PKEY_CTX_new_from_name(None, ALGORITHM.encode(), None)
        if not ctx:
            raise PolicyViolation(f"este OpenSSL no ofrece {ALGORITHM}")
        crypto.EVP_PKEY_CTX_free(ctx)
        _cache = crypto
        return crypto


def _octets(key: bytes, data: bytes) -> tuple[OSSL_PARAM, ctypes.Array]:
    buf = ctypes.create_string_buffer(data, len(data))
    return OSSL_PARAM(key, OSSL_PARAM_OCTET_STRING, ctypes.cast(buf, vp), len(data), 0), buf


def _params(context: bytes, deterministic: bool = False):
    if not isinstance(context, (bytes, bytearray)) or len(context) > CONTEXT_MAX:
        raise MalformedMessage(f"el contexto debe ser bytes de hasta {CONTEXT_MAX} bytes")
    items, keep = [], []
    if context:
        p, b = _octets(b"context-string", bytes(context))
        items.append(p)
        keep.append(b)
    if deterministic:
        det = ctypes.c_int(1)
        items.append(OSSL_PARAM(b"deterministic", OSSL_PARAM_INTEGER, ctypes.cast(ctypes.pointer(det), vp), ctypes.sizeof(det), 0))
        keep.append(det)
    items.append(OSSL_PARAM(None, 0, None, 0, 0))   # terminador
    return (OSSL_PARAM * len(items))(*items), keep


def _import(c, selection: int, **parts: bytes):
    ctx = c.EVP_PKEY_CTX_new_from_name(None, ALGORITHM.encode(), None)
    if not ctx or c.EVP_PKEY_fromdata_init(ctx) != 1:
        raise PolicyViolation("no se pudo preparar la importación de la clave")
    items, keep = [], []
    for k, v in parts.items():
        p, b = _octets(k.encode(), v)
        items.append(p)
        keep.append(b)
    items.append(OSSL_PARAM(None, 0, None, 0, 0))
    arr = (OSSL_PARAM * len(items))(*items)
    pkey = vp()
    ok = c.EVP_PKEY_fromdata(ctx, ctypes.byref(pkey), selection, arr)
    c.EVP_PKEY_CTX_free(ctx)
    if ok != 1 or not pkey:
        raise MalformedMessage("clave SLH-DSA inválida")
    return pkey


def _get(c, pkey, name: bytes, size: int) -> bytes:
    buf, n = ctypes.create_string_buffer(size), sz(0)
    if c.EVP_PKEY_get_octet_string_param(pkey, name, buf, size, ctypes.byref(n)) != 1 or n.value != size:
        raise PolicyViolation("no se pudo exportar la clave")
    return buf.raw[:size]


class SlhDsaPrivateKey:
    """Clave privada (64 bytes) y pública (32 bytes) de SLH-DSA-SHA2-128s."""

    def __init__(self, sk: bytes, pk: bytes) -> None:
        self._sk, self._pk = bytes(sk), bytes(pk)

    @classmethod
    def generate(cls) -> "SlhDsaPrivateKey":
        c = _crypto()
        ctx = c.EVP_PKEY_CTX_new_from_name(None, ALGORITHM.encode(), None)
        pkey = vp()
        try:
            if not ctx or c.EVP_PKEY_keygen_init(ctx) != 1 or c.EVP_PKEY_keygen(ctx, ctypes.byref(pkey)) != 1 or not pkey:
                raise PolicyViolation("falló la generación de clave SLH-DSA")
            return cls(_get(c, pkey, b"priv", SK_LEN), _get(c, pkey, b"pub", PK_LEN))
        finally:
            if pkey:
                c.EVP_PKEY_free(pkey)
            if ctx:
                c.EVP_PKEY_CTX_free(ctx)

    @classmethod
    def from_bytes(cls, sk: bytes) -> "SlhDsaPrivateKey":
        if len(sk) != SK_LEN:
            raise MalformedMessage(f"la clave privada SLH-DSA mide {SK_LEN} bytes")
        # la parte pública son los últimos 32 bytes de la privada (FIPS 205 §9.1: SK = SK.seed ‖ SK.prf ‖ PK.seed ‖ PK.root)
        return cls(sk, bytes(sk[PK_LEN:]))

    def private_bytes(self) -> bytes:
        return self._sk

    def public_bytes(self) -> bytes:
        return self._pk

    def sign(self, message: bytes, context: bytes = b"", deterministic: bool = False) -> bytes:
        c = _crypto()
        pkey = _import(c, EVP_PKEY_KEYPAIR, priv=self._sk, pub=self._pk)
        mctx = c.EVP_MD_CTX_new()
        params, keep = _params(context, deterministic)
        try:
            if c.EVP_DigestSignInit_ex(mctx, None, None, None, None, pkey, params) != 1:
                raise PolicyViolation("falló la preparación de la firma")
            sig, n, expected = ctypes.create_string_buffer(SIG_LEN), sz(SIG_LEN), SIG_LEN
            msg = ctypes.create_string_buffer(bytes(message), max(len(message), 1))
            if c.EVP_DigestSign(mctx, sig, ctypes.byref(n), msg, len(message)) != 1 or n.value != expected:
                raise PolicyViolation("falló la firma")
            return sig.raw[:SIG_LEN]
        finally:
            c.EVP_MD_CTX_free(mctx)
            c.EVP_PKEY_free(pkey)


def slhdsa_verify(pk: bytes, message: bytes, sig: bytes, context: bytes = b"") -> None:
    """Lanza AuthenticationFailure si la firma no es válida (falla cerrado ante cualquier error del puente)."""
    if len(pk) != PK_LEN or len(sig) != SIG_LEN:
        raise MalformedMessage("clave pública o firma SLH-DSA con longitud inválida")
    c = _crypto()
    pkey = _import(c, EVP_PKEY_PUBLIC_KEY, pub=bytes(pk))
    mctx = c.EVP_MD_CTX_new()
    params, keep = _params(context)
    try:
        if c.EVP_DigestVerifyInit_ex(mctx, None, None, None, None, pkey, params) != 1:
            raise AuthenticationFailure("no se pudo preparar la verificación")
        s = ctypes.create_string_buffer(bytes(sig), len(sig))
        msg = ctypes.create_string_buffer(bytes(message), max(len(message), 1))
        if c.EVP_DigestVerify(mctx, s, len(sig), msg, len(message)) != 1:
            raise AuthenticationFailure("firma SLH-DSA inválida")
    finally:
        c.EVP_MD_CTX_free(mctx)
        c.EVP_PKEY_free(pkey)
