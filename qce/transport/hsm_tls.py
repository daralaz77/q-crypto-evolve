"""Servidor TLS 1.3 híbrido cuya CLAVE PRIVADA vive en un HSM o token PKCS#11 y NUNCA entra en este proceso. ESTADO: puente NO REVISADO por terceros.

Cómo: se carga el proveedor PKCS#11 de OpenSSL (`pkcs11-provider`) en un CONTEXTO DE BIBLIOTECA PROPIO (aislado del resto del proceso) desde un archivo de configuración que aporta quien despliega; la clave se
obtiene por su URI (`pkcs11:token=…;object=…;type=private?pin-source=file:…`) mediante el almacén de OpenSSL (`OSSL_STORE`) y se entrega a `SSL_CTX_use_PrivateKey`. A partir de ahí, la firma de
CertificateVerify la hace el token: el proceso solo manipula un manejador opaco. Es la ventanilla del ejemplo: se le pasa el papel para firmar y vuelve firmado.

CICLO DE VIDA (importante): un módulo PKCS#11 se inicializa UNA vez por proceso y no debe descargarse. Liberar el contexto de biblioteca tras el `SSL_CTX` descargaba el módulo y dejaba manejadores de `fork`
colgando: el siguiente `subprocess` terminaba en SIGSEGV (hallazgo real, INC-0027). Por eso el contexto de biblioteca se crea una vez por configuración y vive hasta el final del proceso; `close()` solo libera
el `SSL_CTX`. Consecuencia: un único archivo de configuración de HSM por proceso.

Falla CERRADO y sin alternativa en software: sin proveedor, sin token, con PIN erróneo, sin la clave, o si el certificado no corresponde a la clave del token, no hay servidor. Reutiliza el puente de
`tls13_psk` (mismos grupos, suites, atestación, plazos, cola de errores por hilo). Probado con SoftHSM; ningún HSM real.
"""
from __future__ import annotations

import ctypes
import socket
import threading
from pathlib import Path

from ..core.errors import PolicyViolation
from . import tls13_psk as P

vp, cp, ci = ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int
OSSL_STORE_INFO_PKEY = 4   # NAME=1, PARAMS=2, PUBKEY=3, PKEY=4, CERT=5, CRL=6
_SIGS = [("OSSL_LIB_CTX_new", vp, []), ("OSSL_LIB_CTX_free", None, [vp]), ("OSSL_LIB_CTX_load_config", ci, [vp, cp]),
         ("OSSL_STORE_open_ex", vp, [cp, vp, cp, vp, vp, vp, vp, vp]), ("OSSL_STORE_load", vp, [vp]), ("OSSL_STORE_eof", ci, [vp]),
         ("OSSL_STORE_close", ci, [vp]), ("OSSL_STORE_INFO_get_type", ci, [vp]), ("OSSL_STORE_INFO_get1_PKEY", vp, [vp]),
         ("OSSL_STORE_INFO_free", None, [vp]), ("EVP_PKEY_free", None, [vp]), ("EVP_PKEY_get_bn_param", ci, [vp, cp, ctypes.POINTER(vp)]), ("BN_free", None, [vp])]
_prepared = False
_LIBCTX: dict[str, int] = {}      # un contexto de biblioteca (y su módulo PKCS#11) por configuración, vivo hasta que termine el proceso
_LIBCTX_LOCK = threading.Lock()


def _prepare(crypto) -> None:
    global _prepared
    if not _prepared:
        for name, res, args in _SIGS:
            fn = getattr(crypto, name)
            fn.restype, fn.argtypes = res, args
        _prepared = True


def key_is_extractable(crypto, pkey) -> bool:
    """¿Se puede leer el material privado de esta clave desde el proceso? Una clave de un HSM real (no exportable) NO ofrece sus parámetros privados: RSA «d», EC «priv»."""
    _prepare(crypto)
    for name in (b"d", b"priv"):
        bn = vp()
        if crypto.EVP_PKEY_get_bn_param(pkey, name, ctypes.byref(bn)) == 1:
            if bn:
                crypto.BN_free(bn)
            return True
        P._errors(crypto)   # vacía la cola de errores de este hilo
    return False


class HsmServerContext:
    """Contexto de servidor reutilizable: `accept(sock)` por conexión. Cierre con `close()`."""

    def __init__(self, config_file: str | Path, cert_file: str | Path, key_uri: str, suite: str = P.CIPHERSUITE, group: str = P.GROUP) -> None:
        P._check_suite(suite)
        P._check_group(group)
        if not key_uri.startswith("pkcs11:") or "type=private" not in key_uri:
            raise PolicyViolation("la clave debe indicarse como URI PKCS#11 de una clave privada (pkcs11:…;type=private)")
        for f in (config_file, cert_file):
            if not Path(f).is_file():
                raise PolicyViolation(f"no existe el archivo {Path(f).name}")
        self._lib = P._load()
        l, c = self._lib
        _prepare(c)
        self._suite, self._group = suite, group
        self._ctx = None
        self._libctx = self._libctx_for(c, config_file)
        try:
            self._ctx = P._new_ctx(self._lib, True, suite, group, libctx=self._libctx)
            if l.SSL_CTX_use_certificate_chain_file(self._ctx, str(cert_file).encode()) != 1:
                raise PolicyViolation("certificado no válido: " + P._errors(c))
            self._load_key(key_uri)
            if l.SSL_CTX_check_private_key(self._ctx) != 1:
                raise PolicyViolation("el certificado no corresponde a la clave del token: " + P._errors(c))
        except BaseException:
            self.close()
            raise

    @staticmethod
    def _libctx_for(crypto, config_file) -> int:
        key = str(Path(config_file).resolve())
        with _LIBCTX_LOCK:
            if key not in _LIBCTX:
                libctx = crypto.OSSL_LIB_CTX_new()
                if not libctx or crypto.OSSL_LIB_CTX_load_config(libctx, key.encode()) != 1:
                    detail = P._errors(crypto)
                    raise PolicyViolation("no se pudo cargar la configuración de proveedores (¿falta el proveedor PKCS#11?): " + detail)   # el contexto a medias NO se libera (ver ciclo de vida)
                _LIBCTX[key] = libctx
            return _LIBCTX[key]

    def _load_key(self, uri: str) -> None:
        l, c = self._lib
        store = c.OSSL_STORE_open_ex(uri.encode(), self._libctx, None, None, None, None, None, None)
        if not store:
            raise PolicyViolation("no se pudo abrir la clave en el token (token, PIN o URI incorrectos): " + P._errors(c))
        pkey = None
        try:
            while not pkey and not c.OSSL_STORE_eof(store):
                info = c.OSSL_STORE_load(store)
                if not info:
                    continue
                try:
                    if c.OSSL_STORE_INFO_get_type(info) == OSSL_STORE_INFO_PKEY:
                        pkey = c.OSSL_STORE_INFO_get1_PKEY(info)
                finally:
                    c.OSSL_STORE_INFO_free(info)
            if not pkey:
                raise PolicyViolation("el token no tiene esa clave privada, o no se pudo iniciar sesión (¿PIN o token incorrectos?)")
            if key_is_extractable(c, pkey):
                raise PolicyViolation("la clave es exportable: no está protegida por un HSM (no se usa)")
            ok = l.SSL_CTX_use_PrivateKey(self._ctx, pkey) == 1   # SSL_CTX toma su propia referencia
            if not ok:
                raise PolicyViolation("no se pudo asociar la clave del token al contexto TLS: " + P._errors(c))
        finally:
            if pkey:
                c.EVP_PKEY_free(pkey)
            c.OSSL_STORE_close(store)

    def accept(self, sock: socket.socket, timeout: float = P.HANDSHAKE_TIMEOUT) -> P.PskTlsConnection:
        l, _ = self._lib
        P._nodelay(sock)
        sock.setblocking(False)
        l.SSL_CTX_up_ref(self._ctx)           # cada conexión cierra SU referencia al contexto
        ssl_p = l.SSL_new(self._ctx)
        l.SSL_set_fd(ssl_p, sock.fileno())
        conn = P.PskTlsConnection(self._lib, sock, ssl_p, self._ctx, [], b"")
        try:
            conn._io(lambda: l.SSL_accept(ssl_p), timeout, "apretón")
            P._attest(conn, self._suite, self._group, require_psk=False)
        except BaseException:
            conn.close()
            raise
        return conn

    def close(self) -> None:
        l, c = self._lib
        if self._ctx:
            l.SSL_CTX_free(self._ctx)
            self._ctx = None
        self._libctx = None   # NO se libera: el módulo PKCS#11 vive hasta el final del proceso
