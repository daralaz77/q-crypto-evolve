"""Registro append-only encadenado por hash (evidencia de manipulación, no inmutabilidad).

Un atacante con escritura total puede reescribir TODA la cadena; por eso `head()` debe
anclarse fuera del sistema (repositorio, sello de tiempo, otra máquina).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import time
from pathlib import Path
from typing import Any, Callable

from .errors import IntegrityError

GENESIS = "0" * 64

# Redacción de secretos y datos que permitirían reconstruirlos.
_REDACT = [
    (re.compile(r"-----BEGIN [A-Z ]+-----.*?-----END [A-Z ]+-----", re.S), "[REDACTED-PEM]"),
    (re.compile(r"\b[0-9a-fA-F]{48,}\b"), "[REDACTED-HEX]"),
    (re.compile(r"\b[A-Za-z0-9+/_-]{64,}={0,2}"), "[REDACTED-B64]"),
    (re.compile(r"(?i)(password|passphrase|secret|token|api[_-]?key)(\s*[=:]\s*)\S+"), r"\1\2[REDACTED]"),
]


def sanitize(value: Any) -> Any:
    if isinstance(value, (bytes, bytearray)):
        return f"[BYTES len={len(value)}]"
    if isinstance(value, str):
        for rx, rep in _REDACT:
            value = rx.sub(rep, value)
        return value
    if isinstance(value, dict):
        return {str(k): sanitize(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [sanitize(v) for v in value]
    return value


def _digest(index: int, ts: float, prev: str, body: str) -> str:
    return hashlib.sha256(f"{index}|{ts!r}|{prev}|{body}".encode()).hexdigest()


class ChainLog:
    def __init__(self, path: str | Path, clock: Callable[[], float] = time.time) -> None:
        self.path = Path(path)
        self._clock = clock
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def entries(self) -> list[dict]:
        if not self.path.exists():
            return []
        return [json.loads(line) for line in self.path.read_text().splitlines() if line.strip()]

    def head(self) -> str:
        es = self.entries()
        return es[-1]["hash"] if es else GENESIS

    def append(self, event: dict) -> dict:
        es = self.entries()
        prev = es[-1]["hash"] if es else GENESIS
        body = json.dumps(sanitize(event), sort_keys=True, ensure_ascii=False)
        ts = self._clock()
        entry = {"i": len(es), "ts": ts, "prev": prev, "body": body, "hash": _digest(len(es), ts, prev, body)}
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        return entry

    def verify(self, expected_head: str | None = None) -> int:
        prev = GENESIS
        es = self.entries()
        for n, e in enumerate(es):
            if e["i"] != n or e["prev"] != prev or not hmac.compare_digest(e["hash"], _digest(n, e["ts"], prev, e["body"])):
                raise IntegrityError(f"cadena rota en la entrada {n}")
            prev = e["hash"]
        if expected_head is not None and prev != expected_head:
            raise IntegrityError("la cabeza de la cadena no coincide con el ancla externa (truncado o reescritura)")
        return len(es)
