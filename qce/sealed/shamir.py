"""Reparto de secretos de Shamir sobre GF(2^8), byte a byte (polinomio 0x11B). Sin verificación propia: la detección de participaciones falsas la dan los
compromisos de quien lo usa. LÍMITE: Python no garantiza tiempo constante."""
from __future__ import annotations

import os

from ..core.errors import PolicyViolation


# ---------------------------------------------------------------------------------------------------------------- Shamir sobre GF(2^8)
def _mul(a: int, b: int) -> int:
    """Producto en GF(2^8) (polinomio 0x11B) sin ramas ni tablas dependientes del secreto (Python no garantiza tiempo constante)."""
    r = 0
    for _ in range(8):
        r ^= -(b & 1) & a
        a = ((a << 1) & 0xFF) ^ (-(a >> 7) & 0x1B)
        b >>= 1
    return r


def _inv(a: int) -> int:
    if a == 0:
        raise ValueError("0 no tiene inverso")
    r, e, base = 1, 254, a
    while e:  # el exponente es público
        if e & 1:
            r = _mul(r, base)
        base = _mul(base, base)
        e >>= 1
    return r


def split(secret: bytes, k: int, n: int) -> dict[int, bytes]:
    if not 1 <= k <= n <= 255:
        raise PolicyViolation("umbral inválido")
    coeffs = [secret] + [os.urandom(len(secret)) for _ in range(k - 1)]
    shares = {}
    for x in range(1, n + 1):
        y = bytearray(len(secret))
        for c in reversed(coeffs):  # Horner
            for i in range(len(secret)):
                y[i] = _mul(y[i], x) ^ c[i]
        shares[x] = bytes(y)
    return shares


def combine(shares: dict[int, bytes]) -> bytes:
    """Interpolación de Lagrange en 0. Con menos participaciones que el umbral devuelve basura (no hay error: lo detecta el compromiso)."""
    xs = list(shares)
    if not xs or any(not 1 <= x <= 255 for x in xs):
        raise PolicyViolation("participaciones inválidas")
    out = bytearray(len(shares[xs[0]]))
    for xi in xs:
        num, den = 1, 1
        for xj in xs:
            if xj != xi:
                num = _mul(num, xj)
                den = _mul(den, xj ^ xi)
        w = _mul(num, _inv(den))
        for i in range(len(out)):
            out[i] ^= _mul(shares[xi][i], w)
    return bytes(out)
