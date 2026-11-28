"""Diario encadenado y AUTENTICADO (guardián de candado y custodios).

Cada entrada es una línea JSON canónica `{data, mac, n, type}` cuyo `mac` (HMAC-SHA256 con una clave que solo tiene su dueño) cubre el `mac` anterior: sin la clave no
se puede añadir, cambiar, quitar de en medio ni reordenar nada. Tres defensas más:

- **Anclas** (`anchor`, una o varias): otros archivos, cada uno idealmente en un medio DISTINTO, con la cabeza autenticada. Detectan que se corte el final del diario o
  se restaure una copia vieja: para ocultarlo hay que restaurar a la vez el diario y TODAS las anclas. Sin ancla ni `pinned_head`, un corte del final no se detecta.
- **Cabeza fijada** (`pinned_head`): la misma comprobación contra un valor anotado a mano fuera del equipo.
- **Reloj que no retrocede:** cada entrada lleva su instante; no se anota nada si el reloj está más de 5 minutos antes del último (retrasar el reloj resucitaría
  solicitudes caducadas). Quien entrega rechaza además lo que caducó antes del último apunte; un latido periódico (`tick`) acorta esa ventana.

Quien tiene la clave del diario puede reescribirlo entero.
"""
from __future__ import annotations

import contextlib
import fcntl
import hashlib
import hmac
import json
import os
import time
from collections.abc import Callable, Sequence
from pathlib import Path

from ..core.atomic import atomic_write
from ..core.encoding import lp
from ..core.errors import IntegrityError, PolicyViolation
from ..symmetric.aead import ct_equal
from .envelope import CLOCK_SKEW

GENESIS = bytes(32)
ENTRY_FIELDS = frozenset({"n", "type", "data", "mac"})


def _mac(key: bytes, *parts: bytes) -> bytes:
    return hmac.new(key, b"".join(lp(p) for p in parts), hashlib.sha256).digest()


def _canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


class Journal:
    def __init__(self, path: str | Path, key: bytes, events: dict[str, set[str]], clock: Callable[[], float] = time.time,
                 anchor: str | Path | Sequence[str | Path] | None = None, pinned_head: tuple[int, bytes] | None = None) -> None:
        self.path, self._key, self._clock, self._pin = Path(path), key, clock, pinned_head
        given = () if anchor is None else (anchor,) if isinstance(anchor, (str, Path)) else tuple(anchor)
        self.anchors = tuple(Path(a) for a in given)
        distinct = {str(p.resolve()).casefold() for p in (*self.anchors, self.path)}  # el disco de macOS no distingue mayúsculas
        if len(distinct) != len(self.anchors) + 1:
            raise PolicyViolation("cada ancla debe ser un archivo distinto de las demás y del diario")
        self._events = {kind: fields | {"at"} for kind, fields in events.items()}

    # ------------------------------------------------------------------------------------------------------------ lectura
    def _read_anchor(self, anchor: Path) -> tuple[int, bytes] | None:
        if not anchor.exists():
            return None
        try:
            a = json.loads(anchor.read_text(encoding="utf-8"))
            count, mac, tag = a["n"], bytes.fromhex(a["mac"]), bytes.fromhex(a["tag"])
            if type(count) is not int or count < 1:
                raise ValueError("n")
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise IntegrityError("el ancla del diario está dañada") from exc
        if not ct_equal(tag, _mac(self._key, b"QSEL3/journal-anchor", count.to_bytes(8, "big"), mac)):
            raise IntegrityError("el ancla del diario no está autenticada por este diario")
        return count, mac

    def _check_head(self, entries: list[dict], head: tuple[int, bytes], what: str) -> None:
        count, mac = head
        if count > 0 and (len(entries) < count or not ct_equal(entries[count - 1]["mac"], mac)):
            raise IntegrityError(f"el diario no contiene {what}: se cortó o se sustituyó")

    def _load(self, adopting: bool = False) -> list[dict]:
        """Lee y VERIFICA todo (sin candado: lo pone quien llama). Falla cerrado ante cualquier anomalía. `adopting`: tolera las anclas que aún no existen."""
        anchored = [self._read_anchor(a) for a in self.anchors]
        try:
            text = self.path.read_text(encoding="utf-8") if self.path.exists() else ""
        except (OSError, UnicodeError) as exc:
            raise IntegrityError("el diario no se puede leer") from exc
        if text and not text.endswith("\n"):
            raise IntegrityError("la última entrada del diario está incompleta")
        entries: list[dict] = []
        previous = GENESIS
        for n, line in enumerate(text.splitlines()):
            try:
                e = json.loads(line)
                body = {"n": e["n"], "type": e["type"], "data": e["data"]}
                mac = bytes.fromhex(e["mac"])
                ok = not set(e) ^ ENTRY_FIELDS and e["n"] == n and set(e["data"]) == self._events[e["type"]] and type(e["data"]["at"]) is int
            except (ValueError, KeyError, TypeError, AttributeError) as exc:
                raise IntegrityError(f"entrada {n} del diario ilegible") from exc
            if not ok or not ct_equal(mac, _mac(self._key, b"QSEL3/journal-entry", previous, _canonical(body))):
                raise IntegrityError(f"el diario está roto en la entrada {n} (alterado, reordenado o de otro dueño)")
            previous = mac
            entries.append({**body, "mac": mac})
        for head in anchored:
            if head is not None:
                self._check_head(entries, head, "la cabeza anclada")
            elif entries and not adopting:
                raise IntegrityError("falta el ancla de un diario que ya tiene entradas (si la ancla es nueva, adóptala expresamente)")
        if self._pin is not None:
            self._check_head(entries, self._pin, "la cabeza fijada")
        return entries

    @contextlib.contextmanager
    def _locked(self, mode: int):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path.with_name(self.path.name + ".lock"), "a") as lk:
            fcntl.flock(lk, mode)
            yield

    def read(self) -> list[dict]:
        with self._locked(fcntl.LOCK_SH):
            return self._load()

    def head(self) -> tuple[int, bytes]:
        """(número de entradas, código de la última)."""
        entries = self.read()
        return len(entries), entries[-1]["mac"] if entries else GENESIS

    # ------------------------------------------------------------------------------------------------------------ escritura
    def _write_anchors(self, count: int, mac: bytes, anchors: Sequence[Path]) -> None:
        tag = _mac(self._key, b"QSEL3/journal-anchor", count.to_bytes(8, "big"), mac)
        for anchor in anchors:
            anchor.parent.mkdir(parents=True, exist_ok=True)
            atomic_write(anchor, _canonical({"n": count, "mac": mac.hex(), "tag": tag.hex()}), 0o600)

    def adopt_anchor(self) -> None:
        """Crea las anclas que faltan de un diario que ya existía. Es una decisión EXPRESA: las que ya existen se siguen exigiendo."""
        with self._locked(fcntl.LOCK_EX):
            missing = [a for a in self.anchors if not a.exists()]
            if not missing:
                raise PolicyViolation("no hay ancla que adoptar (sin ruta de ancla, o ya existen todas)")
            entries = self._load(adopting=True)
            if entries:
                self._write_anchors(len(entries), entries[-1]["mac"], missing)

    @contextlib.contextmanager
    def transaction(self):
        """Leer-comprobar-anotar bajo candado exclusivo: dos procesos no pueden atender dos veces lo mismo. Entrega (entradas, anotar)."""
        with self._locked(fcntl.LOCK_EX):
            entries = self._load()

            def append(kind: str, data: dict) -> None:
                now = int(self._clock())
                latest = max((e["data"]["at"] for e in entries), default=now)
                if now < latest - CLOCK_SKEW:
                    raise PolicyViolation("el reloj RETROCEDIÓ respecto al último apunte del diario: no se anota nada")
                previous = entries[-1]["mac"] if entries else GENESIS
                body = {"n": len(entries), "type": kind, "data": {**data, "at": now}}
                mac = _mac(self._key, b"QSEL3/journal-entry", previous, _canonical(body))
                before = self.path.stat().st_size if self.path.exists() else 0
                fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
                try:
                    with os.fdopen(fd, "wb") as fh:
                        fh.write(_canonical({**body, "mac": mac.hex()}) + b"\n")
                        fh.flush()
                        os.fsync(fh.fileno())
                except BaseException:
                    with contextlib.suppress(OSError):
                        os.truncate(self.path, before)
                    raise
                entries.append({**body, "mac": mac})
                self._write_anchors(len(entries), mac, self.anchors)  # si falla, quien llama NO entrega nada: el diario queda por delante del ancla, que es válido
            yield entries, append
