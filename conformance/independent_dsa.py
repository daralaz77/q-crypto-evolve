"""Segunda implementación INDEPENDIENTE de ML-DSA: mldsa-native (PQCA, v2.0.0, commit 834a90d5, Apache-2.0 OR ISC OR MIT), compilada aparte.

  python conformance/build_mldsa_native.py
  python conformance/independent_dsa.py --lib <ruta> [--n 25]     # o QCE_MLDSA_NATIVE_LIB; sale con 1 si algo difiere
Hace tres cosas: (1) ejecuta los vectores Wycheproof de VERIFICACIÓN (65/87) con la API nativa; (2) los de FIRMA a partir de semilla: la clave pública derivada debe
coincidir y la firma de referencia debe verificar; además compara la firma determinista (aleatoriedad cero) con la del vector cuando éste no es aleatorizado;
(3) diferencial contra `cryptography`/OpenSSL con semillas aleatorias: misma clave pública, firmar con uno y verificar con el otro, y firma alterada rechazada por ambos.
Límite: mldsa-native está verificado con CBMC según su proyecto (no lo repetí). Los casos con longitudes erróneas no caben en la API de tamaño fijo de C y se omiten (se cuentan)."""
import ctypes
import json
import os
import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_wycheproof as rw  # noqa: E402

SIZES = {"65": (1952, 4032, 3309), "87": (2592, 4896, 4627)}  # pk, sk, firma
ZERO32 = bytes(32)


class NativeDsa:
    def __init__(self, path: str) -> None:
        self.lib = ctypes.CDLL(path)
        for n in SIZES:
            for fn in ("keypair_internal", "signature_internal", "signature", "verify", "verify_extmu", "signature_extmu"):
                getattr(self.lib, f"mldsa{n}_{fn}").restype = ctypes.c_int

    def keypair(self, n: str, seed: bytes) -> tuple[bytes, bytes]:
        pk, sk = ctypes.create_string_buffer(SIZES[n][0]), ctypes.create_string_buffer(SIZES[n][1])
        assert getattr(self.lib, f"mldsa{n}_keypair_internal")(pk, sk, seed) == 0
        return pk.raw, sk.raw

    def sign_det(self, n: str, msg: bytes, ctx: bytes, sk: bytes) -> bytes:
        """Firma determinista (aleatoriedad cero) con el prefijo estándar 0x00 || len(ctx) || ctx."""
        sig = ctypes.create_string_buffer(SIZES[n][2])
        pre = bytes([0, len(ctx)]) + ctx
        assert getattr(self.lib, f"mldsa{n}_signature_internal")(sig, msg, len(msg), pre, len(pre), ZERO32, sk, 0) == 0
        return sig.raw

    def sign_det_mu(self, n: str, mu: bytes, sk: bytes) -> bytes:
        sig = ctypes.create_string_buffer(SIZES[n][2])
        assert getattr(self.lib, f"mldsa{n}_signature_internal")(sig, mu, len(mu), None, 0, ZERO32, sk, 1) == 0
        return sig.raw

    def sign(self, n: str, msg: bytes, ctx: bytes, sk: bytes) -> bytes:  # API normal (aleatorizada con el RNG DE PRUEBA de la biblioteca: solo para el diferencial)
        sig = ctypes.create_string_buffer(SIZES[n][2])
        assert getattr(self.lib, f"mldsa{n}_signature")(sig, msg, len(msg), ctx, len(ctx), sk) == 0
        return sig.raw

    def verify(self, n: str, sig: bytes, msg: bytes, ctx: bytes, pk: bytes) -> bool:
        return getattr(self.lib, f"mldsa{n}_verify")(sig, msg, len(msg), ctx, len(ctx), pk) == 0

    def verify_mu(self, n: str, sig: bytes, mu: bytes, pk: bytes) -> bool:
        return getattr(self.lib, f"mldsa{n}_verify_extmu")(sig, mu, pk) == 0


def wycheproof_native(nat: NativeDsa, tamper=None) -> dict:
    rep = {"ok": True, "archivos": {}}
    for n, (pk_len, sk_len, sig_len) in SIZES.items():
        out = {"ejecutadas": 0, "omitidas_por_tamaño": 0, "fallos": []}
        for g in rw.load(f"mldsa_{n}_verify_test", tamper)["testGroups"]:
            pk = bytes.fromhex(g["publicKey"] or "")
            for t in g["tests"]:
                sig, msg = bytes.fromhex(t["sig"]), bytes.fromhex(t["msg"])
                ctx = bytes.fromhex(t["ctx"]) if t.get("ctx") else b""
                if len(pk) != pk_len or len(sig) != sig_len or len(ctx) > 255:
                    out["omitidas_por_tamaño"] += 1
                    continue
                out["ejecutadas"] += 1
                if nat.verify(n, sig, msg, ctx, pk) != (t["result"] == "valid"):
                    out["fallos"].append(t["tcId"])
        rep["archivos"][f"mldsa_{n}_verify_test"] = out
        out = {"ejecutadas": 0, "omitidas_por_tamaño": 0, "fallos": [], "firma_determinista_identica_al_vector": 0, "vectores_aleatorizados_no_comparados": 0}
        for g in rw.load(f"mldsa_{n}_sign_seed_test", tamper)["testGroups"]:
            seed = bytes.fromhex(g["privateSeed"])
            if len(seed) != 32 or not g.get("publicKey"):
                out["omitidas_por_tamaño"] += len(g["tests"])
                continue
            pk, sk = nat.keypair(n, seed)
            if pk != bytes.fromhex(g["publicKey"]):
                out["fallos"].append("clave pública derivada distinta")
                continue
            for t in g["tests"]:
                if t["result"] != "valid":
                    out["omitidas_por_tamaño"] += 1
                    continue
                out["ejecutadas"] += 1
                ref = bytes.fromhex(t["sig"])
                if "msg" in t:
                    ctx = bytes.fromhex(t["ctx"]) if t.get("ctx") else b""
                    ok = nat.verify(n, ref, bytes.fromhex(t["msg"]), ctx, pk)
                    det = nat.sign_det(n, bytes.fromhex(t["msg"]), ctx, sk)
                else:
                    ok = nat.verify_mu(n, ref, bytes.fromhex(t["mu"]), pk)
                    det = nat.sign_det_mu(n, bytes.fromhex(t["mu"]), sk)
                if "Randomized" in t.get("flags", []):  # vector firmado con aleatoriedad: la determinista no tiene por qué coincidir
                    out["vectores_aleatorizados_no_comparados"] += 1
                elif det == ref:
                    out["firma_determinista_identica_al_vector"] += 1
                else:
                    ok = False  # un vector DETERMINISTA debe reproducirse byte a byte
                if not ok:
                    out["fallos"].append(t["tcId"])
        rep["archivos"][f"mldsa_{n}_sign_seed_test"] = out
    for name, o in rep["archivos"].items():
        if o["ejecutadas"] < 60:
            o["fallos"].append(f"solo {o['ejecutadas']} ejecutadas")
        rep["ok"] &= not o["fallos"]
    return rep


def differential_native(nat: NativeDsa, n_rounds: int = 25) -> dict:
    from cryptography.hazmat.primitives.asymmetric import mldsa
    API = {"65": mldsa.MLDSA65PrivateKey, "87": mldsa.MLDSA87PrivateKey}
    diffs, done = [], 0
    for _ in range(n_rounds):
        for n, priv_t in API.items():
            seed, msg = secrets.token_bytes(32), secrets.token_bytes(48)
            mine = priv_t.from_seed_bytes(seed)
            pk, sk = nat.keypair(n, seed)
            if pk != mine.public_key().public_bytes_raw():
                diffs.append(f"{n}: clave pública distinta con la misma semilla")
                continue
            ok_native_sig = True
            try:
                mine.public_key().verify(nat.sign(n, msg, b"", sk), msg)  # nativo firma, cryptography verifica
            except Exception:  # noqa: BLE001
                ok_native_sig = False
            if not ok_native_sig:
                diffs.append(f"{n}: una firma nativa no la acepta cryptography")
            sig = mine.sign(msg)  # cryptography firma, nativo verifica
            if not nat.verify(n, sig, msg, b"", pk):
                diffs.append(f"{n}: una firma de cryptography no la acepta el nativo")
            bad = bytearray(sig)
            bad[11] ^= 1
            try:
                mine.public_key().verify(bytes(bad), msg)
                py_accepts = True
            except Exception:  # noqa: BLE001
                py_accepts = False
            if py_accepts or nat.verify(n, bytes(bad), msg, b"", pk):
                diffs.append(f"{n}: una firma alterada fue aceptada")
            done += 1
    return {"rondas": done, "diferencias": diffs, "ok": not diffs and done == 2 * n_rounds}


if __name__ == "__main__":
    lib = sys.argv[sys.argv.index("--lib") + 1] if "--lib" in sys.argv else os.environ.get("QCE_MLDSA_NATIVE_LIB")
    if not lib or not Path(lib).exists():
        sys.exit("indica la biblioteca con --lib o QCE_MLDSA_NATIVE_LIB (ver conformance/build_mldsa_native.py)")
    n = int(sys.argv[sys.argv.index("--n") + 1]) if "--n" in sys.argv else 25
    nat = NativeDsa(lib)
    rep = {"wycheproof_nativo": wycheproof_native(nat), "diferencial": differential_native(nat, n)}
    rep["ok"] = rep["wycheproof_nativo"]["ok"] and rep["diferencial"]["ok"]
    print(json.dumps(rep, indent=1, ensure_ascii=False))
    sys.exit(0 if rep["ok"] else 1)
