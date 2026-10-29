"""Descarga mlkem-native (commit fijado, SHA-256 verificado) y lo compila como biblioteca compartida SIN usar aleatoriedad propia (solo la API `derand`).

  python conformance/build_mlkem_native.py        # imprime la ruta de la biblioteca; luego: export QCE_MLKEM_NATIVE_LIB=<ruta>
El código descargado es NO CONFIABLE hasta compilarlo: se extrae a un directorio nuevo bajo conformance/build/ (ignorado por git) y se compila allí;
no se ejecuta nada de él fuera del compilador. Fuente: https://github.com/pq-code-package/mlkem-native (v2.0.0). Licencia: Apache-2.0 OR ISC OR MIT."""
import hashlib
import shutil
import subprocess
import sys
import tarfile
import urllib.request
from pathlib import Path

COMMIT = "d1b2fe782888bdb761a50336012923180be7f502"
SHA256 = "7c7a10464ba3c62d5657a70da495539ab7f28e464cff80eb9d8173e2bc91c4d3"
URL = f"https://codeload.github.com/pq-code-package/mlkem-native/tar.gz/{COMMIT}"
BUILD = Path(__file__).resolve().parent / "build"


def build() -> Path:
    ext = ".dylib" if sys.platform == "darwin" else ".so"
    out = BUILD / f"libmlkemnative-{COMMIT[:8]}{ext}"
    if out.exists():
        return out
    shutil.rmtree(BUILD, ignore_errors=True)
    BUILD.mkdir(parents=True)
    data = urllib.request.urlopen(URL, timeout=120).read()  # noqa: S310 (URL fija, https)
    if hashlib.sha256(data).hexdigest() != SHA256:
        raise SystemExit("el SHA-256 del paquete fuente no coincide: no se compila")
    tgz = BUILD / "src.tar.gz"
    tgz.write_bytes(data)
    with tarfile.open(tgz) as t:
        t.extractall(BUILD / "src", filter="data")  # filtro «data»: sin rutas absolutas ni enlaces fuera del destino
    ex = next((BUILD / "src").glob("*/examples/monolithic_build_multilevel"))
    subprocess.run(["cc", "-O2", "-std=c99", "-fPIC", "-shared", "-I.", "-Imlkem_native", "-Itest_only_rng", "mlkem_native_all.c",
                    "test_only_rng/notrandombytes.c", "-o", str(out)], cwd=ex, check=True)
    return out


if __name__ == "__main__":
    print(build())
