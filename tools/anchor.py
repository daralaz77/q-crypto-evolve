"""Ancla EXTERNA del libro de incidentes y del registro de confianza (ruta R1 de docs/RUTAS_NUEVAS.md).

Problema (LIMITATIONS.md): la cadena de hashes detecta manipulación parcial, pero quien reescriba TODA la cadena (o cambie el registro de confianza)
no es detectado si no hay una referencia fuera del repositorio. Solución: el flujo `anchor.yml` firma con Sigstore (atestación de GitHub, registrada en un
registro de transparencia público) un resumen DETERMINISTA del estado: cabeza de la cadena, número de entradas, hash del registro de confianza, hash de las
firmas humanas, `release_id` y commit. Como el resumen se puede regenerar desde cualquier commit, no hace falta ningún índice: quien quiera comprobar un
commit lo regenera y pregunta si existe una atestación con ese hash. Una historia reescrita produce otros hashes ⇒ no hay atestación ⇒ se nota.

  python tools/anchor.py                      # imprime el resumen (JSON determinista) del árbol actual
  python tools/anchor.py --commit <sha>       # lo mismo, fijando el commit que figura en el resumen (el flujo de CI)
  python tools/anchor.py --extends anchor.json    # ¿el libro actual EXTIENDE al anclado? (mismo prefijo, cadena íntegra); sale con 1 si no
  python tools/anchor.py --verify-commit <sha> --repo dueño/repo   # regenera el resumen de ese commit y verifica su atestación con `gh`

Límites: la atestación prueba que ESTE flujo, en ESTE repositorio, firmó ese resumen en ese momento; no prueba que el contenido sea correcto. Quien controle la
cuenta de GitHub podría cambiar el flujo; por eso el hash también queda en el registro público de Sigstore, que no controla el repositorio."""
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from qce.core.chainlog import ChainLog  # noqa: E402
from qce.recovery.release import build_manifest  # noqa: E402

SCHEMA = "qce-ledger-anchor/1"


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build(root: Path, commit: str | None = None) -> dict:
    ledger_path = root / "learning" / "incidents.jsonl"
    log = ChainLog(ledger_path)
    entries = log.verify()  # lanza IntegrityError si la cadena está rota: no se ancla una cadena rota
    reviews = sorted((p.name, _sha(p)) for p in (root / "reviews").glob("*.json")) if (root / "reviews").is_dir() else []
    return {
        "schema": SCHEMA,
        "commit": commit if commit is not None else _git_head(root),
        "ledger": {"file": "learning/incidents.jsonl", "entries": entries, "head": log.head()},
        "trust_registry_sha256": _sha(root / "trust" / "registry.json"),
        "reviews_sha256": hashlib.sha256(json.dumps(reviews).encode()).hexdigest(),
        "release_id": build_manifest(root, "anchor", {}, [], {})["release_id"],
    }


def _git_head(root: Path) -> str | None:
    try:
        r = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True)
    except FileNotFoundError:  # sin git (p. ej. el contenedor mínimo de CI): el commit se pasa con --commit
        return None
    return r.stdout.strip() if r.returncode == 0 else None


def render(anchor: dict) -> str:
    return json.dumps(anchor, indent=1, sort_keys=True, ensure_ascii=False) + "\n"


def extends(root: Path, anchored: dict) -> tuple[bool, str]:
    """¿El libro de `root` contiene la entrada anclada en su misma posición (mismo prefijo) y la cadena sigue íntegra?"""
    log = ChainLog(root / "learning" / "incidents.jsonl")
    try:
        total = log.verify()
    except Exception as e:  # noqa: BLE001
        return False, f"la cadena actual está rota: {e}"
    n = anchored["ledger"]["entries"]
    if total < n:
        return False, f"el libro tiene {total} entradas y el ancla tenía {n}: se truncó"
    entries = log.entries()
    got = entries[n - 1]["hash"] if n else "0" * 64
    if got != anchored["ledger"]["head"]:
        return False, "la entrada anclada ya no tiene el mismo hash: la cadena se reescribió"
    return True, f"el libro extiende al anclado ({n} → {total} entradas)"


def verify_commit(sha: str, repo: str) -> int:
    sha = subprocess.run(["git", "rev-parse", sha], cwd=ROOT, capture_output=True, text=True, check=True).stdout.strip()  # SHA COMPLETO: el resumen incluye el commit tal cual y el flujo usa el completo
    with tempfile.TemporaryDirectory(prefix="qce-anchor-") as td:
        tree = Path(td) / "tree"
        tree.mkdir()
        tar = subprocess.run(["git", "archive", sha], cwd=ROOT, capture_output=True, check=True).stdout
        subprocess.run(["tar", "-x", "-C", str(tree)], input=tar, check=True)
        out = Path(td) / "anchor.json"
        out.write_text(render(build(tree, commit=sha)))
        r = subprocess.run(["gh", "attestation", "verify", str(out), "--repo", repo], capture_output=True, text=True)
        print(r.stdout + r.stderr)
        return r.returncode


if __name__ == "__main__":
    a = sys.argv
    if "--extends" in a:
        ok, why = extends(ROOT, json.loads(Path(a[a.index("--extends") + 1]).read_text()))
        print(why)
        sys.exit(0 if ok else 1)
    if "--verify-commit" in a:
        sys.exit(verify_commit(a[a.index("--verify-commit") + 1], a[a.index("--repo") + 1]))
    sys.stdout.write(render(build(ROOT, a[a.index("--commit") + 1] if "--commit" in a else None)))
