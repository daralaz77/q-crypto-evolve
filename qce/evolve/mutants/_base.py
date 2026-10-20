"""Definición de un mutante (una rotura deliberada de UNA garantía). Los datos están en los módulos de esta carpeta, uno por familia."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Mutant:
    name: str
    path: str
    edits: tuple[tuple[str, str], ...]  # (original, mutado); cada original debe aparecer
    guarantee: str
    equivalent_reason: str = ""  # no vacío = declarado equivalente
