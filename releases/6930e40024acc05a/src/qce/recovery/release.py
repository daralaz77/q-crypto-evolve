"""Versionado verificable, clasificación de fallos/cambios y reversión segura (nunca toca claves)."""
from __future__ import annotations

import hashlib
import hmac
import json
import shutil
import time
from pathlib import Path

from ..core.errors import IntegrityError, QCEError

CODE_GLOBS = ("qce", "tests", "requirements.lock", "pytest.ini", "gates.json")

# --- nivel de reparación según lo que toca el cambio (sección 7 del skill) --------------
LEVEL3 = ("qce/core/chainlog.py", "gates.json", "qce/security/scanners.py", "learning/")
LEVEL2 = ("qce/pqc/", "qce/protocols/", "qce/key_management/", "qce/core/policy.py", "qce/symmetric/",
          "qce/qkd/", "requirements.lock")


def change_level(paths: list[str]) -> int:
    """3 = bloqueado hasta autorización; 2 = revisión; 1 = automático."""
    level = 1
    for p in paths:
        if any(p.startswith(x) for x in LEVEL3):
            return 3
        if any(p.startswith(x) for x in LEVEL2):
            level = 2
    return level


def classify_failure(text: str) -> tuple[str, str]:
    """(categoría de causa raíz, pista). Heurística: el humano confirma la causa real."""
    t = text.lower()
    rules = [
        ("dependencia", ("modulenotfounderror", "importerror", "no matching distribution", "unsupportedalgorithm")),
        ("configuracion", ("policyviolation", "suite rechazada", "parámetros kdf")),
        ("protocolo", ("replaydetected", "fuera de orden", "downgrade", "degrad")),
        ("codigo", ("did not raise", "assertionerror", "typeerror", "keyerror", "attributeerror")),
        ("especificacion", ("test vector", "kat", "acvp")),
    ]
    for cat, keys in rules:
        if any(k in t for k in keys):
            return cat, f"coincide con {[k for k in keys if k in t][0]!r}"
    return "desconocida", "sin patrón: requiere análisis manual"


def _hash_tree(root: Path) -> dict[str, str]:
    out = {}
    for g in CODE_GLOBS:
        base = root / g
        files = [base] if base.is_file() else sorted(base.rglob("*.py")) if base.is_dir() else []
        for f in files:
            if "__pycache__" not in f.parts:
                out[str(f.relative_to(root))] = hashlib.sha256(f.read_bytes()).hexdigest()
    return out


def build_manifest(root: Path, version: str, results: dict, risks: list[str], deps: dict[str, str]) -> dict:
    files = _hash_tree(root)
    body = {"version": version, "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "files": files, "dependencies": deps, "results": results, "known_risks": risks,
            "approval": "pendiente"}
    body["release_id"] = hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest()[:16]
    return body


def save_release(root: Path, manifest: dict) -> Path:
    d = root / "releases" / manifest["release_id"]
    d.mkdir(parents=True, exist_ok=True)
    (d / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True))
    src = d / "src"
    if src.exists():
        shutil.rmtree(src)
    for rel in manifest["files"]:
        dst = src / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(root / rel, dst)
    return d


def verify_release(root: Path, release_id: str) -> None:
    d = root / "releases" / release_id
    m = json.loads((d / "manifest.json").read_text())
    for rel, h in m["files"].items():
        f = d / "src" / rel
        if not f.exists() or not hmac.compare_digest(hashlib.sha256(f.read_bytes()).hexdigest(), h):
            raise IntegrityError(f"snapshot manipulado o incompleto: {rel}")


def mark_stable(root: Path, release_id: str, approver: str) -> None:
    if not approver:
        raise QCEError("marcar estable requiere un aprobador humano")
    verify_release(root, release_id)
    (root / "releases" / "STABLE").write_text(json.dumps({"release_id": release_id, "approver": approver}))


def rollback(root: Path, release_id: str | None = None) -> list[str]:
    """Restaura SOLO código y pruebas desde un snapshot verificado.

    No toca vault, claves, contadores, registros de auditoría ni el libro de incidentes:
    revertirlos podría resucitar claves revocadas o borrar evidencia.
    """
    if release_id is None:
        release_id = json.loads((root / "releases" / "STABLE").read_text())["release_id"]
    verify_release(root, release_id)
    d = root / "releases" / release_id
    restored = []
    for rel in json.loads((d / "manifest.json").read_text())["files"]:
        if rel.startswith(("learning/", "vault")):
            continue
        shutil.copy2(d / "src" / rel, root / rel)
        restored.append(rel)
    return restored
