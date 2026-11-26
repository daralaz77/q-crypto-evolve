"""Reparto de la clave MAESTRA de un candado entre varios guardianes (k de n).

Con una sola copia, perderla es perder todos los archivos que cierra; con copias completas, una sola basta para abrirlo todo. Repartida k de n: se toleran n−k
pérdidas, hacen falta k personas para usarla y «destruirla» exige destruir n−k+1 partes (sigue sin poder demostrarse sin hardware especial).

Cada parte lleva los compromisos de TODAS: al reunirlas se identifica la falsa, y la maestra reconstruida debe cumplir el suyo.
"""
from __future__ import annotations

from dataclasses import dataclass

from ..core.errors import AuthenticationFailure, PolicyViolation
from ..symmetric.aead import ct_equal
from .envelope import Lock, _h
from .shamir import combine, split

MAX_SHARES = 16


@dataclass(frozen=True, repr=False)
class LockShare:
    ident: bytes
    label: str
    k: int
    x: int
    share: bytes
    commitments: tuple[str, ...]   # una por parte, en orden (x = 1…n)
    master: str                    # compromiso de la maestra

    def __repr__(self) -> str:  # nunca la parte en trazas
        return f"LockShare({self.label!r}, {self.x}/{len(self.commitments)}, umbral {self.k})"


def _share_commitment(ident: bytes, x: int, share: bytes) -> str:
    return _h(b"QSEL3/lock-share", ident, x.to_bytes(4, "big"), share).hex()


def split_lock(lock: Lock, k: int, n: int) -> list[LockShare]:
    if not 2 <= k <= n <= MAX_SHARES:
        raise PolicyViolation(f"reparto inválido: 2 ≤ umbral ≤ partes ≤ {MAX_SHARES} (con umbral 1 cada parte sería la maestra)")
    shares = split(lock.key, k, n)
    commitments = tuple(_share_commitment(lock.ident, x, shares[x]) for x in range(1, n + 1))
    master = _h(b"QSEL3/lock-master", lock.ident, lock.key).hex()
    return [LockShare(lock.ident, lock.label, k, x, shares[x], commitments, master) for x in range(1, n + 1)]


def join_lock(parts: list[LockShare]) -> Lock:
    if not parts:
        raise PolicyViolation("no hay partes del candado")
    first = parts[0]
    common = (first.ident, first.label, first.k, first.commitments, first.master)
    good: dict[int, bytes] = {}
    for p in parts:
        if (p.ident, p.label, p.k, p.commitments, p.master) != common:
            raise PolicyViolation("las partes son de candados o repartos distintos")
        if not 1 <= p.x <= len(p.commitments) or not ct_equal(bytes.fromhex(p.commitments[p.x - 1]), bytes.fromhex(_share_commitment(p.ident, p.x, p.share))):
            raise AuthenticationFailure(f"la parte {p.x} del candado es falsa o está dañada")
        good[p.x] = p.share
    if len(good) < first.k:
        raise PolicyViolation(f"faltan partes del candado: {len(good)}/{first.k}")
    key = combine({x: good[x] for x in sorted(good)[: first.k]})
    if not ct_equal(bytes.fromhex(first.master), _h(b"QSEL3/lock-master", first.ident, key)):
        raise AuthenticationFailure("la maestra reconstruida no cumple su compromiso: reparto inconsistente")
    return Lock(first.ident, first.label, key)
