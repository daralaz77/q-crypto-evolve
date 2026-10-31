"""Cadena de suministro: hashes de las dependencias fijadas y SBOM CycloneDX, con comprobación de coherencia SIN red.

- `requirements.hashes.txt`: formato de pip (`nombre==versión \\ --hash=sha256:…`) con TODOS los archivos publicados de esa versión en PyPI; permite `pip install --require-hashes`.
- `sbom.cdx.json`: lista de materiales CycloneDX 1.5 de las dependencias de ejecución fijadas (no las de prueba), determinista (sin fecha ni UUID aleatorio).
- Generar (`generate`) necesita red de SOLO LECTURA (API JSON de PyPI); comprobar (`check`) no. Los hashes los publica PyPI: se confía en que PyPI sirve lo que publicó (lo que cubre es la sustitución
  posterior de un archivo; no una dependencia ya maliciosa en su origen). Quién cambie estos archivos cambia el `release_id`.
"""
from __future__ import annotations

import hashlib
import json
import re
import urllib.request
import uuid
from pathlib import Path
from typing import Callable

from ..core.errors import QCEError

HASHES_FILE = "requirements.hashes.txt"
SBOM_FILE = "sbom.cdx.json"
LOCK_LINE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([A-Za-z0-9._+!-]+)$")
SHA = re.compile(r"^[0-9a-f]{64}$")


def read_lock(root: Path) -> list[tuple[str, str]]:
    out = []
    for line in (root / "requirements.lock").read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = LOCK_LINE.match(line)
        if not m:
            raise QCEError(f"línea de requirements.lock no reconocida: {line[:60]!r}")
        out.append((m.group(1).lower(), m.group(2)))
    return out


def fetch_pypi(name: str, version: str, timeout: float = 30.0) -> dict:
    """Metadatos de una versión en PyPI (solo lectura): archivos con su SHA-256 y la licencia declarada."""
    if not LOCK_LINE.match(f"{name}=={version}"):   # el nombre y la versión salen del lock, pero nunca se arman URLs con texto libre
        raise QCEError("nombre o versión de paquete no válidos")
    url = f"https://pypi.org/pypi/{name}/{version}/json"
    with urllib.request.urlopen(url, timeout=timeout) as r:   # noqa: S310 (esquema https fijo arriba)
        data = json.loads(r.read(5_000_000))
    files = sorted({(u["filename"], u["digests"]["sha256"]) for u in data.get("urls", []) if u.get("digests", {}).get("sha256")})
    if not files:
        raise QCEError(f"PyPI no devolvió archivos para {name}=={version}")
    info = data.get("info", {})
    return {"files": files, "license": (info.get("license_expression") or info.get("license") or "")[:120], "summary": (info.get("summary") or "")[:200]}


def hashes_text(entries: list[tuple[str, str, dict]]) -> str:
    out = ["# Generado por `python -m qce supply-chain`. Instalar con: pip install --require-hashes -r requirements.hashes.txt"]
    for name, version, meta in entries:
        hs = sorted({h for _, h in meta["files"]})
        out.append(f"{name}=={version} \\")
        out.append(" \\\n".join(f"    --hash=sha256:{h}" for h in hs))
    return "\n".join(out) + "\n"


def sbom(project_version: str, entries: list[tuple[str, str, dict]]) -> dict:
    comps = []
    for name, version, meta in entries:
        sdists = [h for f, h in meta["files"] if f.endswith((".tar.gz", ".zip"))]
        c = {"type": "library", "bom-ref": f"pkg:pypi/{name}@{version}", "name": name, "version": version, "purl": f"pkg:pypi/{name}@{version}",
             "properties": [{"name": "qce:pypi-artifact-sha256-count", "value": str(len({h for _, h in meta['files']}))}]}
        if sdists:
            c["hashes"] = [{"alg": "SHA-256", "content": sdists[0]}]
        if meta.get("license"):
            c["licenses"] = [{"license": {"name": meta["license"]}}]
        comps.append(c)
    body = {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
            "metadata": {"component": {"type": "application", "name": "q-crypto-evolve", "version": project_version},
                         "properties": [{"name": "qce:scope", "value": "dependencias de ejecución fijadas en requirements.lock (no las de prueba)"}]},
            "components": comps}
    body["serialNumber"] = "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, json.dumps(body, sort_keys=True)))   # determinista: mismo contenido, mismo número
    return body


def generate(root: Path, project_version: str, fetch: Callable[[str, str], dict] = fetch_pypi) -> list[str]:
    entries = [(n, v, fetch(n, v)) for n, v in read_lock(root)]
    (root / HASHES_FILE).write_text(hashes_text(entries), encoding="utf-8")
    (root / SBOM_FILE).write_text(json.dumps(sbom(project_version, entries), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return [f"{n}=={v}" for n, v, _ in entries]


def parse_hashes(text: str) -> dict[str, tuple[str, list[str]]]:
    """{nombre: (versión, [sha256…])} desde el formato de pip con continuaciones de línea."""
    joined = re.sub(r"\\\s*\n\s*", " ", text)
    out: dict[str, tuple[str, list[str]]] = {}
    for line in joined.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        m = LOCK_LINE.match(parts[0])
        if not m:
            raise QCEError(f"línea de hashes no reconocida: {line[:60]!r}")
        hs = []
        for p in parts[1:]:
            if not p.startswith("--hash=sha256:"):
                raise QCEError(f"opción no permitida en el archivo de hashes: {p[:30]!r}")
            hs.append(p.removeprefix("--hash=sha256:"))
        out[m.group(1).lower()] = (m.group(2), hs)
    return out


def check(root: Path) -> list[str]:
    """Problemas de coherencia entre requirements.lock, requirements.hashes.txt y sbom.cdx.json (sin red). Lista vacía = coherente."""
    problems: list[str] = []
    try:
        lock = dict(read_lock(root))
    except (QCEError, OSError) as exc:
        return [f"requirements.lock: {exc}"]
    hf, sf = root / HASHES_FILE, root / SBOM_FILE
    if not hf.exists():
        problems.append(f"falta {HASHES_FILE} (python -m qce supply-chain)")
    else:
        try:
            got = parse_hashes(hf.read_text(encoding="utf-8"))
        except QCEError as exc:
            return problems + [str(exc)]
        for name, ver in lock.items():
            if name not in got:
                problems.append(f"{name} no tiene hashes")
            elif got[name][0] != ver:
                problems.append(f"{name}: versión {ver} en el lock y {got[name][0]} en los hashes")
            elif not got[name][1] or not all(SHA.match(h) for h in got[name][1]):
                problems.append(f"{name}: hashes inválidos o ausentes")
        for name in got:
            if name not in lock:
                problems.append(f"{name} tiene hashes pero no está en el lock")
    if not sf.exists():
        problems.append(f"falta {SBOM_FILE}")
    else:
        try:
            comps = {c["name"].lower(): c["version"] for c in json.loads(sf.read_text(encoding="utf-8")).get("components", [])}
        except (ValueError, KeyError, TypeError):
            return problems + [f"{SBOM_FILE} no es un SBOM válido"]
        if comps != lock:
            problems.append(f"{SBOM_FILE} no coincide con requirements.lock")
    return problems


def file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()
