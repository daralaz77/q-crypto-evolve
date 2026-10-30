"""Escritura atómica y durable de archivos pequeños (vault, ancla de epoch, registro de confianza, declaraciones firmadas).

Temporal en el MISMO directorio → fsync → rename → fsync del directorio: un fallo o un corte a mitad deja el archivo anterior intacto (nunca truncado) y sin
temporales sobrantes. El `rename` es atómico; el `fsync` del directorio hace que sobreviva a un corte de corriente.
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path


def atomic_write(path: str | Path, data: bytes, mode: int = 0o600, prefix: str | None = None) -> None:
    p = Path(path)
    fd, tmp = tempfile.mkstemp(dir=p.parent, prefix=prefix or f".{p.name}-")
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, p)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
    dfd = os.open(p.parent, os.O_RDONLY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)
