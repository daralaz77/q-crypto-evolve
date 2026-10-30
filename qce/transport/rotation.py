"""Planificador de la rotación de la clave/certificado TLS (ítem 1.4 de la Fase 1).

`TlsKeyCustody.rotate_if_due` ya sabe CUÁNDO rotar, pero hay que llamarlo a mano; sin quien lo llame, un certificado caduca y el servicio se cae.
Este planificador lo llama periódicamente. NO decide nada criptográfico: solo programa y registra. No cubre OCSP ni la distribución de CRL (siguen pendientes).
"""
from __future__ import annotations

import threading
import time
from typing import Callable


class RotationScheduler:
    def __init__(self, custody, ca_key, ca_cert, name: str, ttl_s: float, renew_before_s: float, server=None,
                 check_interval_s: float = 60.0, clock: Callable[[], float] = time.time, on_event: Callable[[str, str], None] | None = None) -> None:
        if check_interval_s <= 0 or renew_before_s < 0 or ttl_s <= renew_before_s:
            raise ValueError("intervalo, margen o vida inválidos (la vida debe superar al margen de renovación)")
        self._args = (custody, ca_key, ca_cert, name, ttl_s, renew_before_s, server)
        self.check_interval_s, self._clock, self._on_event = check_interval_s, clock, on_event or (lambda kind, detail: None)
        self.rotations, self.errors, self.last_error = 0, 0, None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def tick(self) -> str | None:
        """Una comprobación. Nunca propaga: un fallo (CA caída, disco lleno…) se cuenta y se reintenta en el próximo ciclo."""
        custody, ca_key, ca_cert, name, ttl_s, renew_before_s, server = self._args
        try:
            new = custody.rotate_if_due(ca_key, ca_cert, name, ttl_s, renew_before_s, server=server)
        except Exception as exc:  # noqa: BLE001
            self.errors += 1
            self.last_error = type(exc).__name__  # solo el tipo: sin secretos en los registros
            self._on_event("error", self.last_error)
            return None
        if new is not None:
            self.rotations += 1
            self._on_event("rotated", new)
        return new

    def start(self) -> "RotationScheduler":
        if self._thread is not None:
            return self
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="qce-rotation", daemon=True)
        self._thread.start()
        return self

    def _run(self) -> None:
        while not self._stop.is_set():
            self.tick()
            self._stop.wait(self.check_interval_s)

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None
