"""Valida la CBOM contra el esquema OFICIAL de CycloneDX 1.6 (github.com/CycloneDX/specification, etiqueta 1.6).

  python conformance/fetch_schemas.py                       # descarga los 3 esquemas (SHA-256 fijado) a ~/.cache/qce-conformance/schema
  ~/.cache/qce-conformance/venv/bin/python tools/validate_cbom.py [archivo]    # necesita `jsonschema` (entorno aislado, fuera del repo)
Sale con 1 si hay errores. Los esquemas se leen solo como datos."""
import hashlib
import json
import os
import sys
from pathlib import Path

from jsonschema import Draft7Validator
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parent.parent
CACHE = Path(os.environ.get("QCE_CONFORMANCE_CACHE", Path.home() / ".cache" / "qce-conformance")) / "schema"
BASE = "http://cyclonedx.org/schema/"


def load_schema_registry() -> tuple[dict, Registry]:
    want = {n: h for h, n in (ln.split() for ln in (ROOT / "conformance" / "schemas.sha256").read_text(encoding="utf-8").splitlines() if ln.strip())}
    docs = {}
    for name, h in want.items():
        raw = (CACHE / name).read_bytes()
        if hashlib.sha256(raw).hexdigest() != h:
            raise SystemExit(f"{name}: el hash no coincide con conformance/schemas.sha256")
        docs[name] = json.loads(raw)
    reg = Registry().with_resources([(BASE + n, Resource.from_contents(d)) for n, d in docs.items()])
    return docs["bom-1.6.schema.json"], reg


def validate(doc: dict) -> list[str]:
    schema, reg = load_schema_registry()
    return sorted(f"{'/'.join(map(str, e.absolute_path)) or '(raíz)'}: {e.message[:160]}" for e in Draft7Validator(schema, registry=reg).iter_errors(doc))


if __name__ == "__main__":
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "benchmarks" / "cbom.cdx.json"
    errs = validate(json.loads(target.read_text(encoding="utf-8")))
    print(json.dumps({"archivo": str(target.name), "errores": errs, "ok": not errs}, indent=1, ensure_ascii=False))
    sys.exit(1 if errs else 0)
