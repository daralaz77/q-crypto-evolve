"""Registro append-only encadenado por hash (evidencia de manipulación, no inmutabilidad).

Un atacante con escritura total puede reescribir TODA la cadena; por eso `head()` debe
anclarse fuera del sistema (repositorio, sello de tiempo, otra máquina).
"""
from __future__ import annotations

import contextlib
import fcntl
import hashlib
import hmac
import json
import math
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
    (re.compile(r"\b[0-9a-fA-F]{32,}\b"), "[REDACTED-HEX]"),
    (re.compile(r"(?:\b[0-9a-fA-F]{2}[:\s-]){15,}[0-9a-fA-F]{2}\b"), "[REDACTED-HEX]"),  # 16+ bytes con separadores
    (re.compile(r"\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{8,}"), "[REDACTED-TOKEN]"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}"), "[REDACTED-TOKEN]"),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"), "[REDACTED-TOKEN]"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*"), "[REDACTED-JWT]"),
    (re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}"), "bearer [REDACTED]"),
    (re.compile(r"(?i)(password|passphrase|secret|token|api[_-]?key)(\s*[=:]\s*)\S+"), r"\1\2[REDACTED]"),
]


_SENSITIVE_KEY = re.compile(r"(?i)(pass(word|phrase|wd)?|secret|token|api[_-]?key|authorization|credential|private|seed)")
_ID_OK = re.compile(r"^(?![0-9a-fA-F]{32,}$)[A-Za-z0-9._-]{1,40}$")  # identificadores estructurales legibles
_TEST_REF = re.compile(r"^tests/[\w./-]+\.py(::\w+)?$")
_ALNUM = re.compile(r"(?<![A-Za-z0-9])[A-Za-z0-9]{32,}(?![A-Za-z0-9])")
_B64 = re.compile(r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{22,}={0,2}(?![A-Za-z0-9+/_-])")


def _entropy(s: str) -> float:
    c = {ch: s.count(ch) for ch in set(s)}
    return -sum(n / len(s) * math.log2(n / len(s)) for n in c.values())


def _looks_like_key_material(tok: str) -> bool:
    """Base64/base64url de claves: alta entropía Y mezcla de clases. No destruye identificadores legibles (p. ej. nombres de prueba)."""
    classes = sum(bool(re.search(p, tok)) for p in (r"[A-Z]", r"[a-z]", r"[0-9]"))  # '/', '+', '=' no cuentan: "a/b/c" no es base64
    if re.fullmatch(r"[a-z0-9_]+", tok):  # snake_case legible (nombres de prueba/función): no es base64
        return False
    return len(tok) >= 22 and classes >= 2 and _entropy(tok.strip("=")) >= 3.6


def _looks_like_alnum_token(tok: str) -> bool:
    return bool(re.search(r"[0-9]", tok) and re.search(r"[A-Za-z]", tok)) and _entropy(tok) >= 3.5


def sanitize(value: Any) -> Any:
    if isinstance(value, (bytes, bytearray)):
        return f"[BYTES len={len(value)}]"
    if isinstance(value, str):
        for rx, rep in _REDACT:
            value = rx.sub(rep, value)
        value = _ALNUM.sub(lambda m: "[REDACTED-TOKEN]" if _looks_like_alnum_token(m.group(0)) else m.group(0), value)
        return _B64.sub(lambda m: "[REDACTED-B64]" if _looks_like_key_material(m.group(0)) else m.group(0), value)
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            ks = sanitize(str(k))
            if _SENSITIVE_KEY.search(str(k)) and isinstance(v, (str, bytes, bytearray)):
                out[ks] = "[REDACTED-BY-KEY]"  # el NOMBRE del campo delata un secreto aunque el valor sea corto
            elif str(k) in ("reproduction_test", "regression_test") and isinstance(v, str) and _TEST_REF.match(v) \
                    and not re.search(r"[0-9a-fA-F]{32,}", v):
                out[ks] = v  # referencia de prueba validada por el libro (no se destruye evidencia)
            elif str(k).endswith("_id") and isinstance(v, str) and _ID_OK.match(v):
                out[ks] = v  # los identificadores legibles no se tocan (se validan al crearlos)
            else:
                out[ks] = sanitize(v)
        return out
    if isinstance(value, (list, tuple)):
        return [sanitize(v) for v in value]
    return value


def _digest(index: int, ts: float, prev: str, body: str) -> str:
    return hashlib.sha256(f"{index}|{ts!r}|{prev}|{body}".encode()).hexdigest()


def _well_formed(e: object) -> bool:
    return (isinstance(e, dict) and type(e.get("i")) is int and isinstance(e.get("ts"), (int, float)) and not isinstance(e.get("ts"), bool)
            and all(isinstance(e.get(k), str) for k in ("prev", "body", "hash")))


def _same(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())  # en bytes: compare_digest sobre str no ASCII lanza TypeError (una entrada manipulada no debe dar otra excepción)


class ChainLog:
    def __init__(self, path: str | Path, clock: Callable[[], float] = time.time) -> None:
        self.path = Path(path)
        self._clock = clock
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def entries(self) -> list[dict]:
        """Lee el registro. FALLA CERRADO (IntegrityError) ante cualquier línea que no sea una entrada completa: un corte a mitad de escritura o un
        truncado dejan una última línea incompleta, y antes eso reventaba con JSONDecodeError (o, peor, la siguiente `append` se pegaba a esa línea)."""
        if not self.path.exists():
            return []
        try:
            text = self.path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as e:
            raise IntegrityError(f"el registro no se puede leer: {type(e).__name__}") from None
        if text and not text.endswith("\n"):
            raise IntegrityError("la última entrada del registro está incompleta (corte a mitad de escritura o truncado)")
        out = []
        for n, line in enumerate(text.splitlines()):
            if not line.strip():
                continue
            try:
                e = json.loads(line)
            except ValueError:
                raise IntegrityError(f"la línea {n + 1} del registro no es JSON válido") from None
            if not _well_formed(e):
                raise IntegrityError(f"la línea {n + 1} del registro no es una entrada válida")
            out.append(e)
        return out

    def head(self) -> str:
        es = self.entries()
        return es[-1]["hash"] if es else GENESIS

    def append(self, event: dict, expected_head: str | None = None) -> dict:
        body = json.dumps(sanitize(event), sort_keys=True, ensure_ascii=False)
        with open(self.path.with_suffix(self.path.suffix + ".lock"), "w") as lk:
            fcntl.flock(lk, fcntl.LOCK_EX)  # leer-último + escribir debe ser atómico entre hilos/procesos
            es = self.entries()
            prev = es[-1]["hash"] if es else GENESIS
            if expected_head is not None and prev != expected_head:  # concurrencia optimista: leer-validar-escribir atómico
                raise IntegrityError("el registro cambió mientras se validaba la operación; reintentar")
            ts = self._clock()
            entry = {"i": len(es), "ts": ts, "prev": prev, "body": body, "hash": _digest(len(es), ts, prev, body)}
            before = self.path.stat().st_size if self.path.exists() else 0
            try:
                with open(self.path, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(entry) + "\n")
                    fh.flush()
                    os.fsync(fh.fileno())
            except BaseException:
                with contextlib.suppress(OSError):
                    os.truncate(self.path, before)  # una escritura a medias (disco lleno, señal) no deja una línea rota que bloquee el registro
                raise
        return entry

    def verify(self, expected_head: str | None = None) -> int:
        prev = GENESIS
        es = self.entries()
        for n, e in enumerate(es):
            if e["i"] != n or e["prev"] != prev or not _same(e["hash"], _digest(n, e["ts"], prev, e["body"])):
                raise IntegrityError(f"cadena rota en la entrada {n}")
            prev = e["hash"]
        if expected_head is not None and prev != expected_head:
            raise IntegrityError("la cabeza de la cadena no coincide con el ancla externa (truncado o reescritura)")
        return len(es)
