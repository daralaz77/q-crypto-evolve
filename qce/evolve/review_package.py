"""Paquete de revisión externa de QCE1: reproducible byte a byte y verificable sin confiar en quien lo envía.

El .zip es determinista (orden, fechas y permisos fijos): dos construcciones del mismo árbol dan el mismo hash.
MANIFEST.sha256 lista el SHA-256 de cada archivo. Importante: el manifiesto NO está firmado; mientras no lo firme una persona,
el hash del .zip debe comunicarse por un canal aparte (ver review/LEEME.md §7).
"""
from __future__ import annotations

import hashlib
import hmac
import importlib.metadata as md
import json
import sys
import zipfile
from pathlib import Path

FIXED_DATE = (2026, 1, 1, 0, 0, 0)
TOP = {  # archivo del repositorio → ruta dentro del paquete
    "review/LEEME.md": "LEEME.md",
    "review/PREGUNTAS_ABIERTAS.md": "PREGUNTAS_ABIERTAS.md",
    "review/REPRODUCCION.md": "REPRODUCCION.md",
    "review/GUIA_PARA_ENVIAR.md": "GUIA_PARA_ENVIAR.md",
    "review/PLANTILLA_INFORME.md": "PLANTILLA_INFORME.md",
    "docs/QCE1_SPEC.md": "docs/QCE1_SPEC.md",
    "docs/QCE1_FORMAL.md": "docs/QCE1_FORMAL.md",
    "docs/QCE1_CONFORMANCE.md": "docs/QCE1_CONFORMANCE.md",
    "formal/qce1.spthy": "formal/qce1.spthy",
    "formal/expected.json": "formal/expected.json",
    "formal/run_all.sh": "formal/run_all.sh",
    "docs/QKD_LAYER_SPEC.md": "docs/QKD_LAYER_SPEC.md",
    "docs/QKD_LAYER_FORMAL.md": "docs/QKD_LAYER_FORMAL.md",
    "docs/QKD_LAYER_CONFORMANCE.md": "docs/QKD_LAYER_CONFORMANCE.md",
    "docs/TLS13_TRANSPORT.md": "docs/TLS13_TRANSPORT.md",
    "docs/TLS13_PSK_TRANSPORT.md": "docs/TLS13_PSK_TRANSPORT.md",
    "docs/ETSI014_ADAPTER.md": "docs/ETSI014_ADAPTER.md",
    "docs/SLHDSA.md": "docs/SLHDSA.md",
    "docs/FUZZ_Y_CARGA.md": "docs/FUZZ_Y_CARGA.md",
    "docs/QKD_TLS_OPTIONS.md": "docs/QKD_TLS_OPTIONS.md",
    "formal/qil1.spthy": "formal/qil1.spthy",
    "formal/expected_qil1.json": "formal/expected_qil1.json",
    "THREAT_MODEL.md": "THREAT_MODEL.md",
    "LIMITATIONS.md": "LIMITATIONS.md",
    "decisions/ADRs.md": "decisions/ADRs.md",
    "learning/incidents.jsonl": "learning/incidents.jsonl",
    "requirements.lock": "requirements.lock",
    "pytest.ini": "pytest.ini",
    "gates.json": "gates.json",
    "tests/vectors/acvp_subset.json": "tests/vectors/acvp_subset.json",
}
TREES = ("qce", "tests")  # solo *.py; nunca __pycache__


def collect(root: Path) -> dict[str, Path]:
    files = {dst: root / src for src, dst in TOP.items()}
    for tree in TREES:
        for p in sorted((root / tree).rglob("*.py")):
            if "__pycache__" not in p.parts:
                files[str(p.relative_to(root))] = p
    missing = [k for k, v in files.items() if not v.is_file()]
    if missing:
        raise FileNotFoundError(f"faltan archivos del paquete: {missing}")
    return files


def _generated(root: Path, files: dict[str, bytes]) -> dict[str, bytes]:
    from ..recovery import release as rel
    test_lock = "\n".join(f"{n}=={md.version(n)}" for n in ("pytest", "hypothesis")) + "\n"
    info = {
        "paquete": "qce1-review", "esquema": 1,
        "release_id_del_codigo": rel.build_manifest(root, "paquete", {}, [], {})["release_id"],
        "python_con_el_que_se_probo": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "cryptography": md.version("cryptography"),
        "tamarin_esperado": "1.12.0", "maude_esperado": "3.5.1",
        "firmado": False,
        "nota": "El manifiesto no está firmado: comunique el hash del .zip por otro canal.",
    }
    return {"requirements-test.lock": test_lock.encode(), "PACKAGE_INFO.json": (json.dumps(info, indent=2, ensure_ascii=False) + "\n").encode()}


def manifest_text(contents: dict[str, bytes]) -> str:
    return "".join(f"{hashlib.sha256(data).hexdigest()}  {name}\n" for name, data in sorted(contents.items()) if name != "MANIFEST.sha256")


def build(root: Path, out_dir: Path) -> tuple[Path, str]:
    files = collect(root)
    contents = {name: p.read_bytes() for name, p in files.items()}
    contents.update(_generated(root, contents))
    manifest = manifest_text(contents)
    contents["MANIFEST.sha256"] = manifest.encode()
    package_id = hashlib.sha256(manifest.encode()).hexdigest()[:16]
    out_dir.mkdir(parents=True, exist_ok=True)
    target = out_dir / f"qce1-review-{package_id}.zip"
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for name in sorted(contents):
            zi = zipfile.ZipInfo(name, FIXED_DATE)
            zi.external_attr = (0o755 if name.endswith(".sh") else 0o644) << 16
            zi.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(zi, contents[name], compresslevel=9)
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    (out_dir / (target.name + ".sha256")).write_text(f"{digest}  {target.name}\n")
    return target, digest


def verify(zip_path: Path) -> list[str]:
    """Problemas encontrados (lista vacía = el contenido coincide con su manifiesto). No comprueba firmas: no las hay."""
    problems = []
    with zipfile.ZipFile(zip_path) as z:
        names = z.namelist()
        for n in names:
            if n.startswith(("/", "..")) or ".." in Path(n).parts:
                problems.append(f"ruta peligrosa en el paquete: {n}")
        if "MANIFEST.sha256" not in names:
            return problems + ["falta MANIFEST.sha256"]
        listed = {}
        for line in z.read("MANIFEST.sha256").decode().splitlines():
            h, _, name = line.partition("  ")
            listed[name] = h
        for name in names:
            if name == "MANIFEST.sha256":
                continue
            if name not in listed:
                problems.append(f"archivo fuera del manifiesto: {name}")
            elif not hmac.compare_digest(hashlib.sha256(z.read(name)).hexdigest(), listed[name]):
                problems.append(f"hash distinto: {name}")
        for name in listed:
            if name not in names:
                problems.append(f"falta el archivo listado: {name}")
    return problems
