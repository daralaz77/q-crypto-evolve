"""Prueba diferencial entre DOS builds de OpenSSL distintos: el embebido en `cryptography` (hoy 4.0.x) y el `openssl` de línea de comandos del sistema (3.5+).
No es independencia total (mismo linaje), pero detecta diferencias de versión/compilación y errores de integración. Una implementación REALMENTE
independiente (mlkem-native, liboqs, libcrux) exige descargar código: ver conformance/README.md.

  python conformance/differential.py [--n 25]   # semillas aleatorias; sale con 1 si hay cualquier diferencia
"""
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import mldsa, mlkem

CLI = shutil.which("openssl")
KEM = {"ML-KEM-768": (mlkem.MLKEM768PrivateKey, mlkem.MLKEM768PublicKey), "ML-KEM-1024": (mlkem.MLKEM1024PrivateKey, mlkem.MLKEM1024PublicKey)}
DSA = {"ML-DSA-65": (mldsa.MLDSA65PrivateKey, mldsa.MLDSA65PublicKey), "ML-DSA-87": (mldsa.MLDSA87PrivateKey, mldsa.MLDSA87PublicKey)}


def sh(*args: str, cwd: Path) -> None:
    subprocess.run([CLI, *args], cwd=cwd, check=True, capture_output=True, env={"PATH": os.environ.get("PATH", ""), "OPENSSL_CONF": "/dev/null"})


def cli_version() -> str:
    return subprocess.run([CLI, "version"], capture_output=True, text=True).stdout.strip()


def pub_der(pub) -> bytes:
    return pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def kem_round(name: str, d: Path, diffs: list) -> None:
    priv_t, pub_t = KEM[name]
    seed = secrets.token_bytes(64)
    mine = priv_t.from_seed_bytes(seed)
    sh("genpkey", "-algorithm", name, "-pkeyopt", f"hexseed:{seed.hex()}", "-out", "k.pem", cwd=d)
    sh("pkey", "-in", "k.pem", "-pubout", "-outform", "DER", "-out", "p.der", cwd=d)
    if (d / "p.der").read_bytes() != pub_der(mine.public_key()):
        diffs.append(f"{name}: la clave pública derivada de la misma semilla difiere")
        return
    sh("pkeyutl", "-encap", "-pubin", "-keyform", "DER", "-inkey", "p.der", "-secret", "ss.bin", "-out", "ct.bin", cwd=d)  # CLI encapsula…
    if mine.decapsulate((d / "ct.bin").read_bytes()) != (d / "ss.bin").read_bytes():  # …cryptography desencapsula
        diffs.append(f"{name}: CLI→cryptography, el secreto compartido difiere")
    ss, ct = sorted(pub_t.from_public_bytes(mine.public_key().public_bytes_raw()).encapsulate(), key=len)  # cryptography encapsula…
    (d / "ct2.bin").write_bytes(ct)
    sh("pkeyutl", "-decap", "-inkey", "k.pem", "-in", "ct2.bin", "-secret", "ss2.bin", cwd=d)  # …CLI desencapsula
    if (d / "ss2.bin").read_bytes() != ss:
        diffs.append(f"{name}: cryptography→CLI, el secreto compartido difiere")
    bad = bytearray(ct)  # rechazo implícito: ambos deben dar el MISMO secreto (determinista) y distinto del honesto
    bad[0] ^= 1
    (d / "ct3.bin").write_bytes(bytes(bad))
    sh("pkeyutl", "-decap", "-inkey", "k.pem", "-in", "ct3.bin", "-secret", "ss3.bin", cwd=d)
    rej = mine.decapsulate(bytes(bad))
    if rej != (d / "ss3.bin").read_bytes() or rej == ss:
        diffs.append(f"{name}: el rechazo implícito difiere entre las dos implementaciones")


def dsa_round(name: str, d: Path, diffs: list) -> None:
    priv_t, pub_t = DSA[name]
    seed, msg = secrets.token_bytes(32), secrets.token_bytes(40)
    mine = priv_t.from_seed_bytes(seed)
    sh("genpkey", "-algorithm", name, "-pkeyopt", f"hexseed:{seed.hex()}", "-out", "d.pem", cwd=d)
    sh("pkey", "-in", "d.pem", "-pubout", "-outform", "DER", "-out", "dp.der", "-provider", "default", cwd=d)
    if (d / "dp.der").read_bytes() != pub_der(mine.public_key()):
        diffs.append(f"{name}: la clave pública derivada de la misma semilla difiere")
        return
    (d / "m.bin").write_bytes(msg)
    sh("pkeyutl", "-sign", "-inkey", "d.pem", "-rawin", "-in", "m.bin", "-out", "s.bin", cwd=d)  # CLI firma, cryptography verifica
    try:
        mine.public_key().verify((d / "s.bin").read_bytes(), msg)
    except Exception:  # noqa: BLE001
        diffs.append(f"{name}: una firma hecha por el CLI no la acepta cryptography")
    sig = mine.sign(msg)  # cryptography firma, CLI verifica
    (d / "s2.bin").write_bytes(sig)
    r = subprocess.run([CLI, "pkeyutl", "-verify", "-pubin", "-keyform", "DER", "-inkey", "dp.der", "-rawin", "-in", "m.bin", "-sigfile", "s2.bin"],
                       cwd=d, capture_output=True, env={"PATH": os.environ.get("PATH", ""), "OPENSSL_CONF": "/dev/null"})
    if r.returncode != 0:
        diffs.append(f"{name}: una firma hecha por cryptography no la acepta el CLI")
    bad = bytearray(sig)
    bad[10] ^= 1  # firma alterada: AMBOS deben rechazarla
    (d / "s3.bin").write_bytes(bytes(bad))
    r = subprocess.run([CLI, "pkeyutl", "-verify", "-pubin", "-keyform", "DER", "-inkey", "dp.der", "-rawin", "-in", "m.bin", "-sigfile", "s3.bin"],
                       cwd=d, capture_output=True, env={"PATH": os.environ.get("PATH", ""), "OPENSSL_CONF": "/dev/null"})
    try:
        mine.public_key().verify(bytes(bad), msg)
        mine_accepts = True
    except Exception:  # noqa: BLE001
        mine_accepts = False
    if mine_accepts or r.returncode == 0:
        diffs.append(f"{name}: una firma alterada fue aceptada (cryptography={mine_accepts}, CLI={r.returncode == 0})")


def run(n: int = 25) -> dict:
    diffs: list = []
    done = 0
    with tempfile.TemporaryDirectory(prefix="qce-diff-") as td:
        d = Path(td)
        for _ in range(n):
            for name in KEM:
                kem_round(name, d, diffs); done += 1
            for name in DSA:
                dsa_round(name, d, diffs); done += 1
    from cryptography.hazmat.backends.openssl.backend import backend
    return {"rondas": done, "diferencias": diffs, "cryptography_openssl": backend.openssl_version_text(), "cli_openssl": cli_version(),
            "ok": not diffs and done == n * (len(KEM) + len(DSA))}


if __name__ == "__main__":
    n = int(sys.argv[sys.argv.index("--n") + 1]) if "--n" in sys.argv else 25
    if not CLI:
        sys.exit("no hay `openssl` en el PATH")
    rep = run(n)
    print(json.dumps(rep, indent=1, ensure_ascii=False))
    sys.exit(0 if rep["ok"] else 1)
