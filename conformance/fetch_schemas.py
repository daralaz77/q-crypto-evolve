"""Descarga los 3 esquemas JSON de CycloneDX 1.6 (etiqueta fija 1.6, SHA-256 verificado) a ~/.cache/qce-conformance/schema."""
import hashlib
import os
import sys
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
CACHE = Path(os.environ.get("QCE_CONFORMANCE_CACHE", Path.home() / ".cache" / "qce-conformance")) / "schema"


def fetch() -> int:
    CACHE.mkdir(parents=True, exist_ok=True)
    bad = 0
    for h, name in (ln.split() for ln in (HERE / "schemas.sha256").read_text().splitlines() if ln.strip()):
        t = CACHE / name
        if t.exists() and hashlib.sha256(t.read_bytes()).hexdigest() == h:
            continue
        data = urllib.request.urlopen(f"https://raw.githubusercontent.com/CycloneDX/specification/1.6/schema/{name}", timeout=60).read()  # noqa: S310
        if hashlib.sha256(data).hexdigest() != h:
            print("HASH DISTINTO:", name, file=sys.stderr)
            bad += 1
            continue
        t.write_bytes(data)
    print("esquemas listos" if not bad else f"{bad} con hash distinto: NO se usan")
    return int(bool(bad))


if __name__ == "__main__":
    sys.exit(fetch())
