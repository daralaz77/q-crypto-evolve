"""Descarga los vectores Wycheproof (commit fijado) y comprueba su SHA-256 contra vectors.manifest.json. Los datos descargados son NO CONFIABLES:
solo se leen como JSON. Uso: python conformance/fetch_vectors.py"""
import hashlib
import json
import sys
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
MANIFEST = json.loads((HERE / "vectors.manifest.json").read_text())
DEST = HERE / "vectors"


def fetch() -> int:
    DEST.mkdir(exist_ok=True)
    bad = 0
    for name, want in MANIFEST["files"].items():
        target = DEST / name
        if target.exists() and hashlib.sha256(target.read_bytes()).hexdigest() == want:
            continue
        url = f"https://raw.githubusercontent.com/C2SP/wycheproof/{MANIFEST['commit']}/{MANIFEST['path']}/{name}"
        data = urllib.request.urlopen(url, timeout=60).read()  # noqa: S310 (URL fija, esquema https)
        got = hashlib.sha256(data).hexdigest()
        if got != want:
            print(f"HASH DISTINTO: {name}", file=sys.stderr)
            bad += 1
            continue
        target.write_bytes(data)
    print("vectores listos" if not bad else f"{bad} archivos con hash distinto: NO se usan")
    return int(bool(bad))


if __name__ == "__main__":
    sys.exit(fetch())
