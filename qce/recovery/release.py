"""Versionado verificable, clasificación de fallos/cambios y reversión segura (nunca toca claves)."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import shutil
import time
from pathlib import Path

from ..core.errors import IntegrityError, QCEError

CODE_GLOBS = ("qce", "tests", "requirements.lock", "pytest.ini", "gates.json", "THREAT_MODEL.md",
              "conftest.py", "sitecustomize.py", "usercustomize.py")
# La reversión SOLO restaura estos prefijos: nunca claves, evidencia, confianza ni umbrales (evita downgrade de gates.json).
ROLLBACK_ALLOWED = ("qce/", "tests/", "requirements.lock", "pytest.ini")

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
        if base.is_symlink():
            raise IntegrityError(f"symlink no permitido en el árbol versionado: {g}")
        everything = [base] if base.is_file() else sorted(base.rglob("*")) if base.is_dir() else []
        for p in everything:  # un symlink (a fichero o a directorio) puede ocultar código ejecutable fuera del hash
            if p.is_symlink():
                raise IntegrityError(f"symlink no permitido en el árbol versionado: {p.relative_to(root)}")
        files = [p for p in everything if p.is_file()]
        for f in files:
            if "__pycache__" not in f.parts and ".hypothesis" not in f.parts:
                out[str(f.relative_to(root))] = hashlib.sha256(f.read_bytes()).hexdigest()
    return out


def build_manifest(root: Path, version: str, results: dict, risks: list[str], deps: dict[str, str]) -> dict:
    files = _hash_tree(root)
    body = {"version": version, "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "files": files, "dependencies": deps, "results": results, "known_risks": risks,
            "approval": "pendiente"}
    body["release_id"] = hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest()[:16]
    rd = root / "releases"
    body["sequence"] = len([p for p in rd.iterdir() if p.is_dir()]) + 1 if rd.exists() else 1
    return body


def _has_symlink(root: Path, rel_path: str) -> bool:
    """¿Algún componente de root/rel_path (sin resolver) es un symlink?"""
    cur = root
    for part in Path(rel_path).parts:
        cur = cur / part
        if cur.is_symlink():
            return True
    return False


def _safe_rel(root: Path, rel_path: str) -> Path:
    """Rechaza rutas absolutas, '..', no normalizadas o que escapen del proyecto (hallazgo 4)."""
    if os.path.isabs(rel_path) or rel_path != os.path.normpath(rel_path) or rel_path.startswith(".."):
        raise IntegrityError(f"ruta no permitida en el manifiesto: {rel_path!r}")
    p = (root / rel_path).resolve()
    if root.resolve() not in p.parents:
        raise IntegrityError(f"ruta fuera del proyecto: {rel_path!r}")
    return p


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
    expected = hashlib.sha256(json.dumps(m["files"], sort_keys=True).encode()).hexdigest()[:16]
    if release_id != expected or m.get("release_id") != expected:  # el id compromete el contenido: no se puede editar un snapshot
        raise IntegrityError("el release_id no corresponde al contenido del manifiesto")
    for rel, h in m["files"].items():
        _safe_rel(root, rel)
        f = d / "src" / rel
        if not f.exists() or not hmac.compare_digest(hashlib.sha256(f.read_bytes()).hexdigest(), h):
            raise IntegrityError(f"snapshot manipulado o incompleto: {rel}")


def mark_stable(root: Path, release_id: str, approver: str) -> None:
    """Requiere una declaración FIRMADA y válida del aprobador para ESTE release; nunca retrocede a una secuencia menor."""
    from ..evolve import approvals  # import tardío: evita ciclo
    if not approver or approver not in approvals.valid_statements(root, release_id, "approver"):
        raise QCEError("marcar estable requiere una declaración firmada y válida de un aprobador registrado")
    verify_release(root, release_id)
    new_seq = json.loads((root / "releases" / release_id / "manifest.json").read_text()).get("sequence", 0)
    cur = root / "releases" / "STABLE"
    if cur.exists():
        old = json.loads(cur.read_text())["release_id"]
        old_seq = json.loads((root / "releases" / old / "manifest.json").read_text()).get("sequence", 0)
        if new_seq < old_seq:
            raise QCEError("downgrade del snapshot estable rechazado (secuencia menor)")
    cur.write_text(json.dumps({"release_id": release_id, "approver": approver}))


def rollback(root: Path, release_id: str | None = None) -> list[str]:
    """Restaura SOLO código y pruebas desde un snapshot verificado.

    No toca vault, claves, contadores, registros de auditoría ni el libro de incidentes:
    revertirlos podría resucitar claves revocadas o borrar evidencia.
    """
    from ..evolve import approvals
    st = json.loads((root / "releases" / "STABLE").read_text())
    if release_id is None:
        release_id = st["release_id"]
    if release_id != st["release_id"] and not approvals.valid_statements(root, release_id, "approver"):
        raise QCEError("revertir a un snapshot que no es el estable exige aprobación firmada")
    if st["approver"] not in approvals.valid_statements(root, st["release_id"], "approver"):
        raise IntegrityError("el marcador STABLE ya no tiene una firma de aprobador válida")
    verify_release(root, release_id)
    d = root / "releases" / release_id
    manifest = json.loads((d / "manifest.json").read_text())
    plan = []
    for rel in manifest["files"]:
        dst = _safe_rel(root, rel)  # comprobación previa de TODAS las rutas antes de escribir nada
        src = d / "src" / rel
        if src.is_symlink() or _has_symlink(root, rel):  # OJO: dst ya está resuelto; hay que mirar la ruta SIN resolver
            raise IntegrityError(f"symlink en la ruta de restauración: {rel}")
        if rel.startswith(ROLLBACK_ALLOWED):  # sin symlinks ni '..' (comprobado arriba) el destino real == rel
            plan.append((rel, dst))
    restored = []
    for rel, dst in plan:
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(d / "src" / rel, dst)
        restored.append(rel)
    return restored
