"""Registro de algoritmos y motor de políticas (anti-degradación)."""
from __future__ import annotations

from dataclasses import dataclass

from .errors import PolicyViolation


@dataclass(frozen=True)
class Suite:
    suite_id: str
    kem: str
    sig: str
    aead: str
    status: str  # "allowed" | "deprecated" | "forbidden"


# Registro central. Añadir una suite aquí NO la habilita: la política decide.
SUITES: dict[str, Suite] = {
    s.suite_id: s
    for s in (
        Suite("QCE1-XMLKEM768-CHACHA", "X25519+ML-KEM-768", "Ed25519+ML-DSA-65", "CHACHA20-POLY1305", "allowed"),
        Suite("QCE1-XMLKEM768-AESGCM", "X25519+ML-KEM-768", "Ed25519+ML-DSA-65", "AES-256-GCM", "allowed"),
        # Ejemplo de suite histórica rechazada siempre (sin componente poscuántico).
        Suite("QCE0-X25519-CHACHA", "X25519", "Ed25519", "CHACHA20-POLY1305", "forbidden"),
    )
}


@dataclass(frozen=True)
class Policy:
    # Orden = preferencia del servidor.
    allowed_suites: tuple[str, ...] = ("QCE1-XMLKEM768-CHACHA", "QCE1-XMLKEM768-AESGCM")
    min_key_bits_symmetric: int = 256
    max_records_per_key: int = 2**32  # rekey mucho antes del límite de nonce de 64 bits
    replay_window: int = 64
    qber_warn: float = 0.05
    qber_abort: float = 0.11  # cota habitual de BB84 con corrección de errores y amplificación
    allow_simulated_qkd: bool = False  # solo laboratorio
    max_handshake_age_s: int = 60

    def __post_init__(self) -> None:
        for sid in self.allowed_suites:
            suite = SUITES.get(sid)
            if suite is None or suite.status != "allowed":
                raise PolicyViolation(f"suite no admisible en la política: {sid}")
            if "+" not in suite.kem or "ML-KEM" not in suite.kem:
                raise PolicyViolation("la política exige KEM híbrido con ML-KEM")

    def check_suite(self, suite_id: str) -> Suite:
        suite = SUITES.get(suite_id)
        if suite is None:
            raise PolicyViolation("suite desconocida")
        if suite.status != "allowed" or suite_id not in self.allowed_suites:
            raise PolicyViolation(f"suite rechazada por política: {suite_id}")
        return suite

    def select(self, offered: list[str]) -> str:
        """Elige según preferencia del servidor; nunca algo fuera de la política."""
        for sid in self.allowed_suites:
            if sid in offered:
                return sid
        raise PolicyViolation("no hay suite común admitida por la política")
