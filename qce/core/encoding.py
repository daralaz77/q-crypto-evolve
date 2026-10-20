"""Codificación binaria estricta (tag, n campos, cada uno con longitud u32)."""
from __future__ import annotations

import struct
from typing import Sequence

from .errors import MalformedMessage

MAX_FIELD = 16384
MAX_FIELDS = 16


def lp(x: bytes) -> bytes:
    """Prefijo de longitud de 4 bytes (big-endian). Lo usan la derivación de la PSK y el transcript de QIL1; `evolve/qil_conformance.py` y las pruebas lo reimplementan A PROPÓSITO como segundo observador independiente."""
    return len(x).to_bytes(4, "big") + x


def pack(tag: int, fields: Sequence[bytes]) -> bytes:
    if not 0 <= tag < 256 or len(fields) > MAX_FIELDS:
        raise MalformedMessage("tag o número de campos fuera de rango")
    out = bytearray(struct.pack(">BB", tag, len(fields)))
    for f in fields:
        if len(f) > MAX_FIELD:
            raise MalformedMessage("campo demasiado grande")
        out += struct.pack(">I", len(f)) + f
    return bytes(out)


def unpack(data: bytes, kind: int, count: int) -> list[bytes]:
    """Rechaza cualquier desviación: tag, número de campos, longitudes y bytes sobrantes."""
    if len(data) < 2:
        raise MalformedMessage("mensaje truncado")
    got_kind, n = struct.unpack(">BB", data[:2])
    if got_kind != kind or n != count:
        raise MalformedMessage("tag o número de campos inesperado")
    pos, fields = 2, []
    for _ in range(n):
        if pos + 4 > len(data):
            raise MalformedMessage("longitud truncada")
        (ln,) = struct.unpack(">I", data[pos : pos + 4])
        pos += 4
        if ln > MAX_FIELD or pos + ln > len(data):
            raise MalformedMessage("longitud inválida")
        fields.append(bytes(data[pos : pos + ln]))
        pos += ln
    if pos != len(data):
        raise MalformedMessage("bytes sobrantes")
    return fields
