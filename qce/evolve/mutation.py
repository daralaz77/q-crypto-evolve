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


SANDBOX_FILES = ("pytest.ini", "THREAT_MODEL.md", "LIMITATIONS.md", "gates.json", "requirements.lock", "requirements.hashes.txt", "sbom.cdx.json")


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


def _run_one(root: Path, m: Mutant, timeout: int) -> dict:
    with tempfile.TemporaryDirectory() as td:
        work = Path(td)
        _sandbox(root, work)
        f = work / m.path
        src = f.read_text()
        for old, new in m.edits:
            if src.count(old) != 1:
                raise RuntimeError(f"mutante {m.name}: el fragmento original aparece {src.count(old)} veces")
            src = src.replace(old, new)
        f.write_text(src)
        t1 = time.time()
        try:
            r = _pytest(work, timeout)
            if r.returncode not in (0, 1):  # 2+ = error de colección/uso: NO es una detección
                raise RuntimeError(f"mutante {m.name}: pytest devolvió {r.returncode} (no es un fallo de prueba)")
            killed = r.returncode == 1
        except subprocess.TimeoutExpired:
            killed = True  # un bucle infinito provocado por el mutante también es detección
        return {"name": m.name, "guarantee": m.guarantee, "killed": killed,
                "equivalent": bool(m.equivalent_reason), "seconds": round(time.time() - t1, 2)}


def run_mutants(root: Path, only: list[str] | None = None, timeout: int = 120) -> dict:
    t0 = time.time()
    # La línea base DEBE ser verde en el sandbox; si no, "todo mutante muere" sería un falso positivo (hallazgo 1 de la auditoría).
    with tempfile.TemporaryDirectory() as td:
        _sandbox(root, Path(td))
        base = _pytest(Path(td), timeout)
        if base.returncode != 0:
            raise RuntimeError("línea base del sandbox NO es verde; la mutación no es válida:\n" + (base.stdout + base.stderr)[-500:])
    if only:
        unknown = sorted(set(only) - {m.name for m in MUTANTS})
        if unknown:
            raise RuntimeError(f"mutantes desconocidos en 'only': {unknown}")
    todo = [m for m in MUTANTS if not only or m.name in only]
    stale = [m.name for m in todo for old, _ in m.edits if (root / m.path).read_text().count(old) != 1]
    if stale:  # falla rápido y claro: un mutante obsoleto no puede contarse como detección ni como superviviente
        raise RuntimeError(f"mutantes con fragmento obsoleto (el código cambió): {stale}")
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:  # cada mutante vive en su propio directorio temporal
        results = list(pool.map(lambda m: _run_one(root, m, timeout), todo))
    canary = next((r for r in results if r["name"].startswith("CANARY")), None)
    if canary and canary["killed"]:
        raise RuntimeError("el mutante canario (sin efecto) fue 'detectado': el arnés de mutación NO es fiable")
    results = [r for r in results if not r["name"].startswith("CANARY")] + ([canary] if canary else [])
    scored = [r for r in results if not r["equivalent"]]
    killed = sum(r["killed"] for r in scored)
    return {"canary_ok": bool(canary) and not canary["killed"], "total": len(results), "scored": len(scored), "killed": killed,
            "score": round(killed / len(scored), 4) if scored else 1.0,
            "survivors": [r["name"] for r in scored if not r["killed"]],
            "declared_equivalent": [r["name"] for r in results if r["equivalent"] and not r["name"].startswith("CANARY")],
            "seconds": round(time.time() - t0, 1), "detail": results}
