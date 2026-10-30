"""Descarga mldsa-native (commit fijado, SHA-256 verificado) y lo compila como biblioteca compartida. Misma cautela que build_mlkem_native.py:
el paquete es NO CONFIABLE hasta compilarlo, se extrae bajo ~/.cache/qce-conformance/ (fuera del repositorio) y solo lo toca el compilador.
Fuente: https://github.com/pq-code-package/mldsa-native (v2.0.0). Licencia: Apache-2.0 OR ISC OR MIT. Uso: python conformance/build_mldsa_native.py"""
import hashlib
import os
import shutil
import subprocess
import sys
import tarfile
import urllib.request
from pathlib import Path

COMMIT = "834a90d5e846ffa1e1611bd24e160bb2e9b86d35"
SHA256 = (Path(__file__).resolve().parent / "mldsa-native.sha256").read_text().split()[0]
URL = f"https://codeload.github.com/pq-code-package/mldsa-native/tar.gz/{COMMIT}"
CACHE = Path(os.environ.get("QCE_CONFORMANCE_CACHE", Path.home() / ".cache" / "qce-conformance"))
BUILD = CACHE / "build-mldsa"


def build() -> Path:
    ext = ".dylib" if sys.platform == "darwin" else ".so"
    out = BUILD / f"libmldsanative-{COMMIT[:8]}{ext}"
    if out.exists():
        return out
    shutil.rmtree(BUILD, ignore_errors=True)
    BUILD.mkdir(parents=True)
    data = urllib.request.urlopen(URL, timeout=120).read()  # noqa: S310 (URL fija, https)
    if hashlib.sha256(data).hexdigest() != SHA256:
        raise SystemExit("el SHA-256 del paquete fuente no coincide: no se compila")
    (BUILD / "src.tar.gz").write_bytes(data)
    with tarfile.open(BUILD / "src.tar.gz") as t:
        t.extractall(BUILD / "src", filter="data")
    ex = next((BUILD / "src").glob("*/examples/monolithic_build_multilevel"))
    subprocess.run(["cc", "-O2", "-std=c99", "-fPIC", "-shared", "-I.", "-Imldsa_native", "-Itest_only_rng", "mldsa_native_all.c",
                    "test_only_rng/notrandombytes.c", "-o", str(out)], cwd=ex, check=True)
    return out


if __name__ == "__main__":
    print(build())
