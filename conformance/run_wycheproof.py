"""Ejecuta los vectores Wycheproof de ML-KEM (768/1024) y ML-DSA (65/87, verificación) contra las primitivas de `cryptography`/OpenSSL
que usa Q-Crypto Evolve. Cubre lo que los vectores ACVP del proyecto NO cubren: ciphertexts/claves de longitud mala, claves de encapsulación
con desbordamiento de módulo, rechazo implícito y firmas ML-DSA inválidas de borde.

  python conformance/run_wycheproof.py            # imprime un resumen JSON; sale con 1 si algo no coincide o si no se ejecutó lo mínimo
Los vectores se leen SOLO como datos (JSON) y se verifican por hash antes de usarlos (ver fetch_vectors.py)."""
import hashlib
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import mldsa, mlkem

HERE = Path(__file__).resolve().parent
MANIFEST = json.loads((HERE / "vectors.manifest.json").read_text())
KEM = {"768": (mlkem.MLKEM768PrivateKey, mlkem.MLKEM768PublicKey, 1184, 1088), "1024": (mlkem.MLKEM1024PrivateKey, mlkem.MLKEM1024PublicKey, 1568, 1568)}
DSA = {"65": mldsa.MLDSA65PublicKey, "87": mldsa.MLDSA87PublicKey}
MINIMUM = {"mlkem_768_test": 150, "mlkem_1024_test": 150, "mlkem_768_encaps_test": 200, "mlkem_1024_encaps_test": 200,
           "mlkem_768_keygen_seed_test": 90, "mlkem_1024_keygen_seed_test": 90, "mldsa_65_verify_test": 190, "mldsa_87_verify_test": 220}


def load(name: str, tamper=None) -> dict:
    raw = (HERE / "vectors" / f"{name}.json").read_bytes()
    if hashlib.sha256(raw).hexdigest() != MANIFEST["files"][f"{name}.json"]:
        raise SystemExit(f"{name}: el hash no coincide con vectors.manifest.json")
    data = json.loads(raw)
    return tamper(name, data) if tamper else data


def _raises(fn) -> bool:
    try:
        fn()
    except Exception:  # noqa: BLE001  (cualquier rechazo cuenta; lo que importa es que NO se acepte)
        return True
    return False


def run_kem_roundtrip(level: str, data: dict, out: dict) -> None:
    priv_t = KEM[level][0]
    for g in data["testGroups"]:
        for t in g["tests"]:
            out["ejecutadas"] += 1
            seed, c = bytes.fromhex(t["seed"]), bytes.fromhex(t["c"])
            if t["result"] == "valid":
                try:
                    priv = priv_t.from_seed_bytes(seed)
                    ok = priv.public_key().public_bytes_raw() == bytes.fromhex(t["ek"]) and priv.decapsulate(c) == bytes.fromhex(t["K"])
                except Exception as e:  # noqa: BLE001
                    ok = False
                    out["errores"].append(f"tc{t['tcId']}: {e!r}")
            else:  # longitud de semilla o de ciphertext incorrecta: debe rechazarse
                ok = _raises(lambda: priv_t.from_seed_bytes(seed).decapsulate(c))
            if not ok:
                out["fallos"].append(t["tcId"])


def run_kem_keygen(level: str, data: dict, out: dict) -> None:
    priv_t = KEM[level][0]
    for g in data["testGroups"]:
        for t in g["tests"]:
            out["ejecutadas"] += 1
            if t["result"] != "valid":
                continue
            ok = priv_t.from_seed_bytes(bytes.fromhex(t["seed"])).public_key().public_bytes_raw() == bytes.fromhex(t["ek"])
            if not ok:
                out["fallos"].append(t["tcId"])
    out["no_comprobado"] = "la clave de desencapsulación expandida (dk) no se puede exportar con esta API: solo se compara ek"


def run_kem_encaps(level: str, data: dict, out: dict) -> None:
    _, pub_t, _, ct_len = KEM[level]
    for g in data["testGroups"]:
        for t in g["tests"]:
            out["ejecutadas"] += 1
            ek = bytes.fromhex(t["ek"])
            if t["result"] == "valid":
                try:
                    r = pub_t.from_public_bytes(ek).encapsulate()
                    ok = sorted(len(x) for x in r) == [32, ct_len]
                except Exception as e:  # noqa: BLE001
                    ok = False
                    out["errores"].append(f"tc{t['tcId']}: {e!r}")
            else:  # clave de encapsulación mal formada o con desbordamiento de módulo: NO debe aceptarse
                ok = _raises(lambda: pub_t.from_public_bytes(ek).encapsulate())
            if not ok:
                out["fallos"].append(t["tcId"])


def run_dsa_verify(level: str, data: dict, out: dict) -> None:
    pub_t = DSA[level]
    for g in data["testGroups"]:
        try:
            pub = pub_t.from_public_bytes(bytes.fromhex(g["publicKey"]))
        except Exception:  # noqa: BLE001
            pub = None
        for t in g["tests"]:
            out["ejecutadas"] += 1
            ctx = bytes.fromhex(t["ctx"]) if t.get("ctx") else None
            accepted = False
            if pub is not None:
                try:
                    pub.verify(bytes.fromhex(t["sig"]), bytes.fromhex(t["msg"]), ctx)
                    accepted = True
                except Exception:  # noqa: BLE001
                    accepted = False
            if (t["result"] == "valid") != accepted and t["result"] in ("valid", "invalid"):
                out["fallos"].append(t["tcId"])


def run_all(tamper=None) -> dict:
    plan = [(f"mlkem_{n}_test", run_kem_roundtrip, n) for n in KEM] + [(f"mlkem_{n}_keygen_seed_test", run_kem_keygen, n) for n in KEM] \
        + [(f"mlkem_{n}_encaps_test", run_kem_encaps, n) for n in KEM] + [(f"mldsa_{n}_verify_test", run_dsa_verify, n) for n in DSA]
    report = {"commit_vectores": MANIFEST["commit"], "archivos": {}, "ok": True}
    for name, fn, level in plan:
        out = {"ejecutadas": 0, "fallos": [], "errores": []}
        fn(level, load(name, tamper), out)
        if out["ejecutadas"] < MINIMUM[name]:  # «0 fallos» con casi nada ejecutado sería un resultado vacío
            out["errores"].append(f"se ejecutaron {out['ejecutadas']} < mínimo {MINIMUM[name]}")
        report["archivos"][name] = out
        report["ok"] &= not out["fallos"] and not out["errores"]
    report["semi_expanded_decaps"] = "no probado aquí: la API no importa claves de desencapsulación expandidas (ver conformance/README.md)"
    return report


if __name__ == "__main__":
    rep = run_all()
    print(json.dumps(rep, indent=1, ensure_ascii=False))
    sys.exit(0 if rep["ok"] else 1)
