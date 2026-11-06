"""Prueba diferencial con una implementación INDEPENDIENTE (kyber-py / dilithium-py, Python puro) frente a OpenSSL 3.6.4 y 4.0.3 (CLI).
Experimento aislado (venv del scratchpad). Semillas deterministas, claves de prueba."""
import subprocess, sys, tempfile, random
import kyber_py.ml_kem as K
import dilithium_py.ml_dsa as D

import os
O = {"o3": os.environ.get("OPENSSL_A", "openssl"), "o4": os.environ.get("OPENSSL_B", "openssl")}   # dos binarios de OpenSSL (idealmente versiones distintas)
N = int(sys.argv[1]) if len(sys.argv) > 1 else 20
INVERT = len(sys.argv) > 2 and sys.argv[2] == "control"          # control negativo: corrompe la semilla del lado puro
rng = random.Random(20261107)
tmp = tempfile.mkdtemp()
fails, checks = [], 0


def run(*a):
    return subprocess.run(a, capture_output=True, timeout=60)


def chk(c, w):
    global checks
    checks += 1
    if not c:
        fails.append(w)


def spki_raw(der):                       # el SPKI DER termina con la clave pública cruda
    return der


def kem(alg, impl, i):
    seed = bytes(rng.randrange(256) for _ in range(64))
    pseed = bytes([seed[0] ^ 1]) + seed[1:] if INVERT else seed
    ek, dk = impl.key_derive(pseed)
    keys = {}
    for n, exe in O.items():
        kp = f"{tmp}/k_{n}.pem"
        r = run(exe, "genpkey", "-algorithm", alg, "-pkeyopt", f"hexseed:{seed.hex()}", "-out", kp)
        chk(r.returncode == 0, f"{alg}#{i} genpkey {n}")
        keys[n] = kp
        chk(run(exe, "pkey", "-in", kp, "-pubout", "-outform", "DER").stdout.endswith(ek), f"{alg}#{i} clave pública {n}≠pura")
    # puro encapsula → OpenSSL desencapsula
    a, b = impl.encaps(ek)
    ss, ct = (a, b) if len(a) == 32 else (b, a)
    for n, exe in O.items():
        open(f"{tmp}/ct", "wb").write(ct)
        run(exe, "pkeyutl", "-decap", "-inkey", keys[n], "-in", f"{tmp}/ct", "-secret", f"{tmp}/ssd")
        chk(open(f"{tmp}/ssd", "rb").read() == ss, f"{alg}#{i} puro→{n}")
    # OpenSSL encapsula → puro desencapsula
    for n, exe in O.items():
        pp = f"{tmp}/p_{n}.pem"
        open(pp, "wb").write(run(exe, "pkey", "-in", keys[n], "-pubout").stdout)
        run(exe, "pkeyutl", "-encap", "-inkey", pp, "-pubin", "-out", f"{tmp}/ct2", "-secret", f"{tmp}/ss2")
        ct2, ss2 = open(f"{tmp}/ct2", "rb").read(), open(f"{tmp}/ss2", "rb").read()
        chk(impl.decaps(dk, ct2) == ss2, f"{alg}#{i} {n}→puro")
        # rechazo implícito
        bad = bytearray(ct2); bad[rng.randrange(len(bad))] ^= 1 << rng.randrange(8); bad = bytes(bad)
        open(f"{tmp}/ct3", "wb").write(bad)
        run(exe, "pkeyutl", "-decap", "-inkey", keys[n], "-in", f"{tmp}/ct3", "-secret", f"{tmp}/ss3")
        chk(open(f"{tmp}/ss3", "rb").read() == impl.decaps(dk, bad) != ss2, f"{alg}#{i} rechazo implícito {n}≠puro")


def dsa(alg, impl, i):
    seed = bytes(rng.randrange(256) for _ in range(32))
    pseed = bytes([seed[0] ^ 1]) + seed[1:] if INVERT else seed
    msg = bytes(rng.randrange(256) for _ in range(rng.choice([1, 17, 200, 1000])))
    pk, sk = impl.key_derive(pseed)
    sig = impl.sign(sk, msg, deterministic=True)
    bad_msg = bytes([msg[0] ^ 1]) + msg[1:]
    bad_sig = bytearray(sig); bad_sig[rng.randrange(len(bad_sig))] ^= 1 << rng.randrange(8); bad_sig = bytes(bad_sig)
    chk(impl.verify(pk, msg, sig) is True and impl.verify(pk, bad_msg, sig) is False and impl.verify(pk, msg, bad_sig) is False, f"{alg}#{i} puro consigo mismo")
    for n, exe in O.items():
        kp = f"{tmp}/d_{n}.pem"
        run(exe, "genpkey", "-algorithm", alg, "-pkeyopt", f"hexseed:{seed.hex()}", "-out", kp)
        open(f"{tmp}/m", "wb").write(msg)
        run(exe, "pkeyutl", "-sign", "-inkey", kp, "-in", f"{tmp}/m", "-rawin", "-pkeyopt", "deterministic:1", "-out", f"{tmp}/s")
        chk(open(f"{tmp}/s", "rb").read() == sig, f"{alg}#{i} firma determinista {n}≠pura")
        run(exe, "pkey", "-in", kp, "-pubout", "-out", f"{tmp}/pub.pem")
        for label, sg, mm, ok in (("ok", sig, msg, True), ("msg-alterado", sig, bad_msg, False), ("firma-alterada", bad_sig, msg, False)):
            open(f"{tmp}/s2", "wb").write(sg); open(f"{tmp}/m2", "wb").write(mm)
            r = run(exe, "pkeyutl", "-verify", "-pubin", "-inkey", f"{tmp}/pub.pem", "-in", f"{tmp}/m2", "-rawin", "-sigfile", f"{tmp}/s2")
            chk((r.returncode == 0) == ok, f"{alg}#{i} {n} verifica {label} (firma pura)")


for i in range(N):
    kem("ML-KEM-768", K.ML_KEM_768, i)
    kem("ML-KEM-1024", K.ML_KEM_1024, i)
    for alg, impl in (("ML-DSA-44", D.ML_DSA_44), ("ML-DSA-65", D.ML_DSA_65), ("ML-DSA-87", D.ML_DSA_87)):
        dsa(alg, impl, i)
print(f"{'CONTROL ' if INVERT else ''}casos por algoritmo: {N}; comprobaciones: {checks}; discrepancias: {len(fails)}")
for f in fails[:12]:
    print("  DIF:", f)
