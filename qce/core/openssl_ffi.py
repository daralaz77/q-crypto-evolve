"""Carga de OpenSSL ≥ 3.5 por `ctypes`: el ÚNICO sitio que decide qué biblioteca se usa y con qué versión mínima. ESTADO: puente NO REVISADO por terceros.

Lo comparten el transporte TLS 1.3 con PSK, el servidor con HSM y la firma SLH-DSA (antes vivía dentro del transporte TLS y obligaba a `pqc` a importar `transport`, un ciclo).
No guarda caché a propósito: cada llamador cachea lo que ya configuró (sus firmas de funciones), y así las pruebas pueden simular «sin OpenSSL» o «OpenSSL antiguo» cambiando `CANDIDATES` u `OPENSSL_MIN`.
Falla CERRADO: sin una biblioteca utilizable ≥ 3.5, `OpenSslUnavailable`; no hay degradación a otra cosa.
"""
from __future__ import annotations

import ctypes
import os

from .errors import QCEError

OPENSSL_MIN = 0x30500000        # 3.5: primer OpenSSL con ML-KEM, SLH-DSA y los híbridos X25519MLKEM768

CANDIDATES = (os.environ.get("QCE_LIBSSL", ""), "/opt/homebrew/opt/openssl@3/lib/libssl.3.dylib", "/usr/local/opt/openssl@3/lib/libssl.3.dylib",
              "/usr/lib/x86_64-linux-gnu/libssl.so.3", "/usr/lib/aarch64-linux-gnu/libssl.so.3", "/usr/lib64/libssl.so.3", "libssl.so.3")


class OpenSslUnavailable(QCEError):
    """No hay una biblioteca OpenSSL utilizable (≥ 3.5): el componente no se degrada, no existe."""


def load(ssl_sigs=()) -> tuple:
    """Devuelve `(libssl, libcrypto)`. `ssl_sigs` = `(nombre, restype, argtypes)` que se fijan sobre `libssl` (las de `libcrypto` las fija cada llamador)."""
    tried = []
    for path in CANDIDATES:
        if not path:
            continue
        try:
            ssl_lib = ctypes.CDLL(path)
            crypto = ctypes.CDLL(os.path.join(os.path.dirname(path), os.path.basename(path).replace("libssl", "libcrypto")) if os.path.dirname(path)
                                 else path.replace("libssl", "libcrypto"))
            crypto.OpenSSL_version_num.restype = ctypes.c_ulong
            if crypto.OpenSSL_version_num() < OPENSSL_MIN:
                tried.append(f"{path}: versión {crypto.OpenSSL_version_num():#x} < 3.5")
                continue
            for name, res, args in ssl_sigs:
                fn = getattr(ssl_lib, name)
                fn.restype, fn.argtypes = res, args
            crypto.ERR_get_error.restype = ctypes.c_ulong
            crypto.ERR_clear_error.restype, crypto.ERR_clear_error.argtypes = None, []
            crypto.ERR_error_string_n.argtypes = [ctypes.c_ulong, ctypes.c_char_p, ctypes.c_size_t]
            return ssl_lib, crypto
        except (OSError, AttributeError) as exc:
            tried.append(f"{path}: {type(exc).__name__}")
    raise OpenSslUnavailable("no hay una biblioteca OpenSSL ≥ 3.5 utilizable (" + "; ".join(tried) + "); defina QCE_LIBSSL")


def errors(crypto) -> str:
    """Vacía la cola de errores de OpenSSL DEL HILO y devuelve hasta tres mensajes."""
    out = []
    while (e := crypto.ERR_get_error()):
        b = ctypes.create_string_buffer(256)
        crypto.ERR_error_string_n(e, b, 256)
        out.append(b.value.decode(errors="replace"))
    return "; ".join(out[:3])
