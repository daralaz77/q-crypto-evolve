"""Pruebas de mutación sobre código crítico: ¿las pruebas detectan un control de seguridad roto?

Cada mutante rompe a propósito UNA garantía. Si las pruebas siguen en verde, hay una laguna
real en la batería (mutante superviviente). Los mutantes equivalentes (no cambian el
comportamiento observable) se declaran explícitamente con su justificación; no se ocultan.
"""
from __future__ import annotations

import shutil
from concurrent.futures import ThreadPoolExecutor
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from .mutants import ALL as MUTANTS  # noqa: E402  (datos en evolve/mutants/, uno por familia)
from .mutants._base import Mutant  # noqa: E402


SANDBOX_FILES = ("pytest.ini", "THREAT_MODEL.md", "LIMITATIONS.md", "gates.json", "requirements.lock", "requirements.hashes.txt", "requirements-test.hashes.txt", "sbom.cdx.json")


def _sandbox(root: Path, work: Path) -> None:
    shutil.copytree(root / "qce", work / "qce", ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copytree(root / "tests", work / "tests", ignore=shutil.ignore_patterns("__pycache__"))
    for f in SANDBOX_FILES:
        if (root / f).exists():
            shutil.copy2(root / f, work / f)
    for d in ("docs", "formal"):  # las pruebas de especificación y conformidad leen estos archivos
        if (root / d).is_dir():
            shutil.copytree(root / d, work / d, ignore=shutil.ignore_patterns("__pycache__"))


def _pytest(work: Path, timeout: int) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-B", "-m", "pytest", "-x", "-q", "-p", "no:cacheprovider"], cwd=work,
                          capture_output=True, text=True, timeout=timeout,
                          env={"PYTHONPATH": str(work), "PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1", "HYPOTHESIS_STORAGE_DIRECTORY": str(work / ".h")})


WORKERS = 6
TIMEOUT_FACTOR = 5          # el límite por mutante es esta vez la duración de la línea base (que corre SOLA; los mutantes corren WORKERS a la vez)
BASELINE_TIMEOUT_S = 1800   # tope de la línea base: si ni así termina, la batería está rota, no lenta
_clock = time.monotonic     # reloj propio para poder simularlo en las pruebas


def effective_timeout(baseline_seconds: float, floor: int) -> int:
    """Límite por mutante: nunca menos que `floor`, y `TIMEOUT_FACTOR` veces lo que tarda la línea base. Un límite fijo (120 s) se queda corto en cuanto la batería crece o el equipo va cargado,
    y un tiempo agotado se cuenta como «detectado»: sin esto, la lentitud se confundiría con detección."""
    return max(int(floor), int(baseline_seconds * TIMEOUT_FACTOR + 0.999))


def _run_one(root: Path, m: Mutant, timeout: int) -> dict:
    with tempfile.TemporaryDirectory() as td:
        work = Path(td)
        _sandbox(root, work)
        f = work / m.path
        src = f.read_text(encoding="utf-8")
        for old, new in m.edits:
            if src.count(old) != 1:
                raise RuntimeError(f"mutante {m.name}: el fragmento original aparece {src.count(old)} veces")
            src = src.replace(old, new)
        f.write_text(src, encoding="utf-8")
        t1 = _clock()
        timed_out = False
        try:
            r = _pytest(work, timeout)
            if r.returncode not in (0, 1):  # 2+ = error de colección/uso: NO es una detección
                raise RuntimeError(f"mutante {m.name}: pytest devolvió {r.returncode} (no es un fallo de prueba)")
            killed = r.returncode == 1
        except subprocess.TimeoutExpired:
            killed, timed_out = True, True  # un bucle infinito provocado por el mutante también es detección (y queda anotado)
        return {"name": m.name, "guarantee": m.guarantee, "killed": killed, "timed_out": timed_out,
                "equivalent": bool(m.equivalent_reason), "seconds": round(_clock() - t1, 2)}


def run_mutants(root: Path, only: list[str] | None = None, timeout: int = 120) -> dict:
    t0 = _clock()
    # La línea base DEBE ser verde en el sandbox; si no, "todo mutante muere" sería un falso positivo (hallazgo 1 de la auditoría).
    with tempfile.TemporaryDirectory() as td:
        _sandbox(root, Path(td))
        tb = _clock()
        try:
            base = _pytest(Path(td), max(timeout, BASELINE_TIMEOUT_S))
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(f"la línea base del sandbox no terminó en {max(timeout, BASELINE_TIMEOUT_S)} s: la batería está colgada o el equipo no da abasto; la mutación no es válida") from exc
        baseline_seconds = _clock() - tb
        if base.returncode != 0:
            raise RuntimeError("línea base del sandbox NO es verde; la mutación no es válida:\n" + (base.stdout + base.stderr)[-500:])
    if only:
        unknown = sorted(set(only) - {m.name for m in MUTANTS})
        if unknown:
            raise RuntimeError(f"mutantes desconocidos en 'only': {unknown}")
    todo = [m for m in MUTANTS if not only or m.name in only]
    stale = [m.name for m in todo for old, _ in m.edits if (root / m.path).read_text(encoding="utf-8").count(old) != 1]
    if stale:  # falla rápido y claro: un mutante obsoleto no puede contarse como detección ni como superviviente
        raise RuntimeError(f"mutantes con fragmento obsoleto (el código cambió): {stale}")
    per_mutant = effective_timeout(baseline_seconds, timeout)
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:  # cada mutante vive en su propio directorio temporal
        results = list(pool.map(lambda m: _run_one(root, m, per_mutant), todo))
    canary = next((r for r in results if r["name"].startswith("CANARY")), None)
    if canary and canary["timed_out"]:
        raise RuntimeError(f"el mutante canario (sin efecto) AGOTÓ el tiempo ({per_mutant} s; la línea base tardó {baseline_seconds:.0f} s): "
                           "es lentitud del equipo, no detección; libera la máquina o sube el límite. El arnés de mutación NO es fiable así")
    if canary and canary["killed"]:
        raise RuntimeError("el mutante canario (sin efecto) fue 'detectado': el arnés de mutación NO es fiable")
    results = [r for r in results if not r["name"].startswith("CANARY")] + ([canary] if canary else [])
    scored = [r for r in results if not r["equivalent"]]
    killed = sum(r["killed"] for r in scored)
    return {"canary_ok": canary is not None and not canary["killed"], "total": len(results), "scored": len(scored), "killed": killed,
            "score": round(killed / len(scored), 4) if scored else 1.0,
            "survivors": [r["name"] for r in scored if not r["killed"]],
            "declared_equivalent": [r["name"] for r in results if r["equivalent"] and not r["name"].startswith("CANARY")],
            "baseline_seconds": round(baseline_seconds, 1), "timeout_s": per_mutant,
            "timed_out": [r["name"] for r in results if r["timed_out"] and not r["name"].startswith("CANARY")],
            "seconds": round(_clock() - t0, 1), "detail": results}
