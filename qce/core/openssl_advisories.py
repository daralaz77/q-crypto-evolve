"""Avisos conocidos de OpenSSL: ¿la versión cargada está por debajo de la que corrige un aviso publicado?

POR QUÉ EXISTE: `openssl_ffi.OPENSSL_MIN` solo exige OpenSSL ≥ 3.5 (que tenga ML-KEM, SLH-DSA y los grupos híbridos). Eso no dice nada de si esa 3.5.x o 3.6.x tiene un
fallo ya corregido. Esta tabla guarda, por rama, la primera versión que corrige el último aviso relevante y `assess` compara.

LÍMITES (declarados, no ocultos):
- Es una TABLA ESCRITA A MANO desde https://openssl-library.org/news/vulnerabilities/ con fecha `AS_OF`. No consulta la red y envejece: `table_age_days` lo mide y la CLI avisa.
- Solo compara el NÚMERO de versión de OpenSSL. Las distribuciones (Debian, Ubuntu, Red Hat…) suelen corregir con parches «retroportados» sin cambiar ese número: una
  versión «por debajo» puede estar ya parcheada. Por eso el resultado es un AVISO y no un error, salvo que se pida `--strict`.
- No sabe si el componente vulnerable lo usa este proyecto (p. ej. DTLS no se usa). Solo dice «hay un aviso que corrige una versión posterior».
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date

SOURCE = "https://openssl-library.org/news/vulnerabilities/"
AS_OF = date(2026, 9, 29)          # fecha de los avisos recogidos en la tabla
STALE_AFTER_DAYS = 180             # pasado este tiempo, la propia tabla se declara desactualizada

# rama (mayor, menor) → (primera versión de parche que lo corrige, aviso, gravedad). Fuente: la página de avisos del 2026-09-29.
BRANCH_FLOORS: dict[tuple[int, int], tuple[int, str, str]] = {
    (3, 5): (9, "CVE-2026-84782", "alta"),
    (3, 6): (5, "CVE-2026-84782", "alta"),
    (4, 0): (3, "CVE-2026-84782 y CVE-2026-84783", "alta"),
}


@dataclass(frozen=True)
class Assessment:
    version: str      # «3.6.4»
    status: str       # "ok" | "below_floor" | "no_data"
    detail: str


def version_tuple(number: int) -> tuple[int, int, int]:
    """`OPENSSL_VERSION_NUMBER` (formato 0xMNN00PP0 de OpenSSL 3.x y 4.x) → (mayor, menor, parche)."""
    return (number >> 28) & 0xF, (number >> 20) & 0xFF, (number >> 4) & 0xFF


def table_age_days(today: date | None = None) -> int:
    return ((today or date.today()) - AS_OF).days


def assess(number: int) -> Assessment:
    major, minor, patch = version_tuple(number)
    version = f"{major}.{minor}.{patch}"
    entry = BRANCH_FLOORS.get((major, minor))
    if entry is None:
        return Assessment(version, "no_data", f"OpenSSL {version}: la tabla no tiene datos de la rama {major}.{minor} (avisos al {AS_OF})")
    floor, advisory, severity = entry
    if patch < floor:
        return Assessment(version, "below_floor",
                          f"AVISO: OpenSSL {version} está por debajo de {major}.{minor}.{floor}, que corrige {advisory} (gravedad {severity}, aviso al {AS_OF}). "
                          "Las distribuciones pueden haberlo parcheado sin cambiar el número de versión: comprueba el aviso de la tuya. "
                          f"Fuente: {SOURCE}")
    return Assessment(version, "ok", f"OpenSSL {version}: al día frente a los avisos de la tabla ({AS_OF})")
