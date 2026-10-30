"""Fuzzer GUIADO POR COBERTURA, sin dependencias (ítem 1.3 de la Fase 1). Usa `sys.monitoring` (Python ≥ 3.12): cada línea nueva del código vigilado cuenta como
cobertura nueva y desactiva su propio evento (coste casi nulo después del descubrimiento). Un input que descubre líneas nuevas entra al corpus y se muta más.

Qué es y qué no es: un fuzzer sencillo, determinista (semilla fija) y reproducible; NO sustituye a AFL++/libFuzzer/Atheris ni fuzzea código C (los puentes `ctypes` con
OpenSSL quedan fuera). «Crash» = una excepción que NO sea una de las que el objetivo declara aceptables (para los parsers: solo `QCEError`)."""
from __future__ import annotations

import random
import sys
import time
from typing import Callable

TOOL = sys.monitoring.PROFILER_ID if hasattr(sys, "monitoring") else None


class GuidedFuzzer:
    def __init__(self, target: Callable[[bytes], object], seeds: list[bytes], accept: tuple[type, ...], watch: Callable[[str], bool], rng_seed: int = 0,
                 max_len: int = 2048, guided: bool = True) -> None:
        if not hasattr(sys, "monitoring"):
            raise RuntimeError("se necesita Python >= 3.12 (sys.monitoring)")
        self.target, self.accept, self.watch, self.max_len, self.guided = target, accept, watch, max_len, guided
        self.rng = random.Random(rng_seed)
        self.corpus: list[bytes] = list(seeds) or [b""]
        self.new_lines = 0
        self.crashes: list[tuple[bytes, str]] = []
        self.executions = 0
        self._seen_in_run = 0

    # ---- cobertura ----
    def _start(self) -> None:
        sys.monitoring.use_tool_id(TOOL, "qce-guided-fuzz")
        sys.monitoring.register_callback(TOOL, sys.monitoring.events.LINE, self._wrap_line)
        sys.monitoring.set_events(TOOL, sys.monitoring.events.LINE)
        sys.monitoring.restart_events()  # reactiva las líneas que una ejecución anterior desactivó: cada ejecución mide su cobertura desde cero

    def _wrap_line(self, code, line):
        # Una línea vigilada que se ve por primera vez es cobertura NUEVA y se desactiva para no volver a contarla.
        if self.watch(code.co_filename):
            self.new_lines += 1
            self._seen_in_run += 1
        return sys.monitoring.DISABLE

    def _stop(self) -> None:
        sys.monitoring.set_events(TOOL, 0)
        sys.monitoring.register_callback(TOOL, sys.monitoring.events.LINE, None)
        sys.monitoring.free_tool_id(TOOL)

    # ---- mutaciones ----
    def mutate(self, data: bytes) -> bytes:
        r, b = self.rng, bytearray(data)
        for _ in range(r.choice((1, 1, 2, 3, 5))):
            op = r.randrange(7)
            if op == 0 and b:
                b[r.randrange(len(b))] ^= 1 << r.randrange(8)
            elif op == 1 and b:
                b[r.randrange(len(b))] = r.randrange(256)
            elif op == 2 and len(b) < self.max_len:
                b.insert(r.randrange(len(b) + 1), r.randrange(256))
            elif op == 3 and len(b) > 1:
                del b[r.randrange(len(b))]
            elif op == 4 and b:
                b[r.randrange(len(b))] = r.choice((0, 1, 2, 0x7F, 0x80, 0xFE, 0xFF))
            elif op == 5 and len(self.corpus) > 1:  # empalme con otro elemento del corpus
                other = r.choice(self.corpus)
                cut = r.randrange(len(b) + 1)
                b = b[:cut] + bytearray(other[r.randrange(len(other) + 1):])
            elif op == 6 and len(b) >= 4:  # tocar un campo de longitud de 4 bytes
                i = r.randrange(len(b) - 3)
                b[i:i + 4] = r.choice((0, 1, 0x4000, 0x4001, 0xFFFFFFFF)).to_bytes(4, "big")
        return bytes(b[: self.max_len])

    # ---- bucle ----
    def run(self, iterations: int = 5000, seconds: float | None = None) -> dict:
        self._start()
        t0 = time.time()
        try:
            for s in list(self.corpus):  # el corpus semilla también cuenta para la cobertura base
                self._exec(s, add=False)
            base = self.new_lines
            for _ in range(iterations):
                if seconds is not None and time.time() - t0 > seconds:
                    break
                parent = self.rng.choice(self.corpus) if self.guided else self.rng.choice(self.corpus[: max(1, len(self.corpus))])
                child = self.mutate(parent)
                before = self.new_lines
                self._exec(child, add=False)
                if self.guided and self.new_lines > before:
                    self.corpus.append(child)  # descubrió líneas nuevas: se conserva y se muta más
        finally:
            self._stop()
        return {"executions": self.executions, "base_lines": base, "total_lines": self.new_lines, "new_lines_beyond_seeds": self.new_lines - base,
                "corpus": len(self.corpus), "crashes": len(self.crashes), "first_crash": self.crashes[0] if self.crashes else None}

    def _exec(self, data: bytes, add: bool) -> None:
        self.executions += 1
        try:
            self.target(data)
        except self.accept:
            pass
        except BaseException as exc:  # noqa: BLE001
            self.crashes.append((data, type(exc).__name__))
