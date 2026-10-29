"""Segunda implementación INDEPENDIENTE de ML-KEM: mlkem-native (PQCA, v2.0.0, commit d1b2fe78, Apache-2.0 OR ISC OR MIT), compilada aparte.

La biblioteca se compila con `conformance/build_mlkem_native.sh` (o a mano) y se indica con QCE_MLKEM_NATIVE_LIB o `--lib`. Aquí hace dos cosas:
  1. Ejecuta los vectores Wycheproof que `cryptography` NO puede ejecutar: encapsulación con aleatoriedad fija (`enc_derand`) y desencapsulación
     con clave expandida (`semi_expanded_decaps`, `check_pk`, `check_sk`). Así los vectores también prueban a mlkem-native.
  2. Diferencial contra `cryptography`/OpenSSL con semillas aleatorias: misma clave pública, encapsular con uno y desencapsular con el otro,
     y mismo secreto de rechazo implícito.

  python conformance/independent.py --lib /ruta/libmlkemnative.so [--n 25]    # sale con 1 si algo difiere
Límite: mlkem-native es código en C verificado con CBMC según su proyecto; no repetí esa verificación. Esto no mide tiempo constante."""
import ctypes
import json
import os
import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_wycheproof as rw  # noqa: E402

SIZES = {"768": (1184, 2400, 1088), "1024": (1568, 3168, 1568)}  # pk, sk, ct


class Native:
    def __init__(self, path: str) -> None:
        self.lib = ctypes.CDLL(path)
        for n in SIZES:
            for fn in ("keypair_derand", "enc_derand", "dec", "check_pk", "check_sk"):
                getattr(self.lib, f"mlkem{n}_{fn}").restype = ctypes.c_int

    def keypair(self, n: str, coins: bytes) -> tuple[bytes, bytes]:
        pk, sk = ctypes.create_string_buffer(SIZES[n][0]), ctypes.create_string_buffer(SIZES[n][1])
        rc = getattr(self.lib, f"mlkem{n}_keypair_derand")(pk, sk, coins)
        assert rc == 0
        return pk.raw, sk.raw

    def enc(self, n: str, pk: bytes, m: bytes) -> tuple[int, bytes, bytes]:
        ct, ss = ctypes.create_string_buffer(SIZES[n][2]), ctypes.create_string_buffer(32)
        rc = getattr(self.lib, f"mlkem{n}_enc_derand")(ct, ss, pk, m)
        return rc, ct.raw, ss.raw

    def dec(self, n: str, ct: bytes, sk: bytes) -> tuple[int, bytes]:
        ss = ctypes.create_string_buffer(32)
        return getattr(self.lib, f"mlkem{n}_dec")(ss, ct, sk), ss.raw

    def check_pk(self, n: str, pk: bytes) -> int:
        return getattr(self.lib, f"mlkem{n}_check_pk")(pk)

    def check_sk(self, n: str, sk: bytes) -> int:
        return getattr(self.lib, f"mlkem{n}_check_sk")(sk)


def wycheproof_native(nat: Native, tamper=None) -> dict:
    rep = {"ok": True, "archivos": {}}
    for n in SIZES:
        pk_len, sk_len, ct_len = SIZES[n]
        # 1) ida y vuelta con semilla (valid) — longitudes malas no caben en la API de tamaño fijo de C: se omiten y se cuentan
        out = {"ejecutadas": 0, "omitidas_por_tamaño": 0, "fallos": []}
        for g in rw.load(f"mlkem_{n}_test", tamper)["testGroups"]:
            for t in g["tests"]:
                if t["result"] != "valid":
                    out["omitidas_por_tamaño"] += 1
                    continue
                out["ejecutadas"] += 1
                pk, sk = nat.keypair(n, bytes.fromhex(t["seed"]))
                rc, ss = nat.dec(n, bytes.fromhex(t["c"]), sk)
                if pk != bytes.fromhex(t["ek"]) or rc != 0 or ss != bytes.fromhex(t["K"]):
                    out["fallos"].append(t["tcId"])
        rep["archivos"][f"mlkem_{n}_test"] = out
        # 2) encapsulación con aleatoriedad fija: ct y K deben coincidir EXACTAMENTE; ek inválida (módulo) debe rechazarse
        out = {"ejecutadas": 0, "omitidas_por_tamaño": 0, "fallos": []}
        for g in rw.load(f"mlkem_{n}_encaps_test", tamper)["testGroups"]:
            for t in g["tests"]:
                ek = bytes.fromhex(t["ek"])
                if len(ek) != pk_len:
                    out["omitidas_por_tamaño"] += 1
                    continue
                out["ejecutadas"] += 1
                if t["result"] == "valid":
                    rc, ct, ss = nat.enc(n, ek, bytes.fromhex(t["m"]))
                    ok = nat.check_pk(n, ek) == 0 and rc == 0 and ct == bytes.fromhex(t["c"]) and ss == bytes.fromhex(t["K"])
                else:
                    ok = nat.check_pk(n, ek) != 0  # ModulusOverflow: debe fallar la comprobación de módulo (FIPS 203 §7.2)
                if not ok:
                    out["fallos"].append(t["tcId"])
        rep["archivos"][f"mlkem_{n}_encaps_test"] = out
        # 3) desencapsulación con clave EXPANDIDA (lo que `cryptography` no puede importar)
        out = {"ejecutadas": 0, "omitidas_por_tamaño": 0, "fallos": []}
        for g in rw.load(f"mlkem_{n}_semi_expanded_decaps_test", tamper)["testGroups"]:
            for t in g["tests"]:
                dk, c = bytes.fromhex(t["dk"]), bytes.fromhex(t["c"])
                if len(dk) != sk_len or len(c) != ct_len:
                    out["omitidas_por_tamaño"] += 1
                    continue
                out["ejecutadas"] += 1
                if t["result"] == "valid":
                    rc, ss = nat.dec(n, c, dk)
                    ok = nat.check_sk(n, dk) == 0 and rc == 0 and ss == bytes.fromhex(t["K"])
                else:
                    ok = nat.check_sk(n, dk) != 0  # clave con hash o ek embebida corrupta: debe rechazarse
                if not ok:
                    out["fallos"].append(t["tcId"])
        rep["archivos"][f"mlkem_{n}_semi_expanded_decaps_test"] = out
    for name, o in rep["archivos"].items():
        if o["ejecutadas"] < 5:
            o["fallos"].append(f"solo {o['ejecutadas']} ejecutadas")
        rep["ok"] &= not o["fallos"]
    return rep


def differential_native(nat: Native, n_rounds: int = 25) -> dict:
    from cryptography.hazmat.primitives.asymmetric import mlkem
    API = {"768": (mlkem.MLKEM768PrivateKey, mlkem.MLKEM768PublicKey), "1024": (mlkem.MLKEM1024PrivateKey, mlkem.MLKEM1024PublicKey)}
    diffs, done = [], 0
    for _ in range(n_rounds):
        for n, (priv_t, pub_t) in API.items():
            seed = secrets.token_bytes(64)
            mine = priv_t.from_seed_bytes(seed)
            pk, sk = nat.keypair(n, seed)
            if pk != mine.public_key().public_bytes_raw():
                diffs.append(f"{n}: clave pública distinta con la misma semilla")
                continue
            rc, ct, ss = nat.enc(n, pk, secrets.token_bytes(32))  # nativo encapsula, cryptography desencapsula
            if rc != 0 or mine.decapsulate(ct) != ss:
                diffs.append(f"{n}: nativo→cryptography, secreto distinto")
            ss2, ct2 = sorted(pub_t.from_public_bytes(pk).encapsulate(), key=len)  # cryptography encapsula, nativo desencapsula
            rc, got = nat.dec(n, ct2, sk)
            if rc != 0 or got != ss2:
                diffs.append(f"{n}: cryptography→nativo, secreto distinto")
            bad = bytearray(ct2)
            bad[7] ^= 1
            rc, rej = nat.dec(n, bytes(bad), sk)  # rechazo implícito: mismo secreto determinista en ambos, y distinto del honesto
            if rc != 0 or rej != mine.decapsulate(bytes(bad)) or rej == ss2:
                diffs.append(f"{n}: el rechazo implícito difiere")
            done += 1
    return {"rondas": done, "diferencias": diffs, "ok": not diffs and done == 2 * n_rounds}


if __name__ == "__main__":
    lib = sys.argv[sys.argv.index("--lib") + 1] if "--lib" in sys.argv else os.environ.get("QCE_MLKEM_NATIVE_LIB")
    if not lib or not Path(lib).exists():
        sys.exit("indica la biblioteca con --lib o QCE_MLKEM_NATIVE_LIB (ver conformance/build_mlkem_native.sh)")
    n = int(sys.argv[sys.argv.index("--n") + 1]) if "--n" in sys.argv else 25
    nat = Native(lib)
    rep = {"wycheproof_nativo": wycheproof_native(nat), "diferencial": differential_native(nat, n)}
    rep["ok"] = rep["wycheproof_nativo"]["ok"] and rep["diferencial"]["ok"]
    print(json.dumps(rep, indent=1, ensure_ascii=False))
    sys.exit(0 if rep["ok"] else 1)
