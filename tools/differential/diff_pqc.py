"""Prueba diferencial ML-KEM / ML-DSA entre OpenSSL 3.6.4 (CLI), OpenSSL 4.0.3 (CLI) y `cryptography` 50.0.2.
Experimento aislado: no toca qce/ ni tests/. Semillas deterministas (no secretas), solo claves de prueba."""
import os
import random
import subprocess
import sys
import tempfile

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization as S
from cryptography.hazmat.primitives.asymmetric import mldsa, mlkem

O = {"o3": os.environ.get("OPENSSL_A", "openssl"), "o4": os.environ.get("OPENSSL_B", "openssl")}   # dos binarios de OpenSSL (idealmente versiones distintas)
N = int(sys.argv[1]) if len(sys.argv) > 1 else 50
rng = random.Random(20261106)
tmp = tempfile.mkdtemp()
fails, checks = [], 0


def run(*a, **k):
    return subprocess.run(a, capture_output=True, timeout=60, **k)


def chk(cond, what):
    global checks
    checks += 1
    if not cond:
        fails.append(what)


def kem_case(alg, cls, i):
    seed = bytes(rng.randrange(256) for _ in range(64))
    keys, pubs = {}, {}
    for n, exe in O.items():
        kp = f"{tmp}/k_{n}.pem"
        r = run(exe, "genpkey", "-algorithm", alg, "-pkeyopt", f"hexseed:{seed.hex()}", "-out", kp)
        chk(r.returncode == 0, f"{alg}#{i} genpkey {n}: {r.stderr[:80]}")
        keys[n] = kp
        pubs[n] = run(exe, "pkey", "-in", kp, "-pubout", "-outform", "DER").stdout
    cr = cls.from_seed_bytes(seed)
    pub_c = cr.public_key().public_bytes(S.Encoding.Raw, S.PublicFormat.Raw)
    chk(pubs["o3"] == pubs["o4"], f"{alg}#{i} clave pública o3≠o4")
    chk(pubs["o3"].endswith(pub_c), f"{alg}#{i} clave pública OpenSSL≠cryptography")
    # encapsular con cada implementación, desencapsular con las otras tres
    for src in ("o3", "o4", "crypto"):
        if src == "crypto":
            ss, ct = cr.public_key().encapsulate()
        else:
            pp = f"{tmp}/p_{src}.pem"
            open(pp, "wb").write(run(O[src], "pkey", "-in", keys[src], "-pubout").stdout)
            run(O[src], "pkeyutl", "-encap", "-inkey", pp, "-pubin", "-out", f"{tmp}/ct", "-secret", f"{tmp}/ss")
            ct, ss = open(f"{tmp}/ct", "rb").read(), open(f"{tmp}/ss", "rb").read()
        for dst in ("o3", "o4"):
            open(f"{tmp}/ctin", "wb").write(ct)
            run(O[dst], "pkeyutl", "-decap", "-inkey", keys[dst], "-in", f"{tmp}/ctin", "-secret", f"{tmp}/ssd")
            chk(open(f"{tmp}/ssd", "rb").read() == ss, f"{alg}#{i} encap {src} → decap {dst}")
        chk(cr.decapsulate(ct) == ss, f"{alg}#{i} encap {src} → decap cryptography")
        # texto cifrado alterado: el secreto de rechazo implícito debe ser idéntico en las tres
        bad = bytearray(ct)
        bad[rng.randrange(len(bad))] ^= 1 << rng.randrange(8)
        bad = bytes(bad)
        outs = [cr.decapsulate(bad)]
        for dst in ("o3", "o4"):
            open(f"{tmp}/ctin", "wb").write(bad)
            run(O[dst], "pkeyutl", "-decap", "-inkey", keys[dst], "-in", f"{tmp}/ctin", "-secret", f"{tmp}/ssd")
            outs.append(open(f"{tmp}/ssd", "rb").read())
        chk(len(set(outs)) == 1 and outs[0] != ss, f"{alg}#{i} rechazo implícito difiere/ coincide con el real (src {src})")


def dsa_case(alg, cls, i):
    seed = bytes(rng.randrange(256) for _ in range(32))
    msg = bytes(rng.randrange(256) for _ in range(rng.choice([1, 17, 200, 1000])))
    keys, sigs = {}, {}
    for n, exe in O.items():
        kp = f"{tmp}/d_{n}.pem"
        r = run(exe, "genpkey", "-algorithm", alg, "-pkeyopt", f"hexseed:{seed.hex()}", "-out", kp)
        chk(r.returncode == 0, f"{alg}#{i} genpkey {n}")
        keys[n] = kp
        open(f"{tmp}/m", "wb").write(msg)
        r = run(exe, "pkeyutl", "-sign", "-inkey", kp, "-in", f"{tmp}/m", "-rawin", "-pkeyopt", "deterministic:1", "-out", f"{tmp}/s")
        chk(r.returncode == 0, f"{alg}#{i} firmar {n}: {r.stderr[:80]}")
        sigs[n] = open(f"{tmp}/s", "rb").read()
    cr = cls.from_seed_bytes(seed)
    sig_c = cr.sign(msg)
    chk(sigs["o3"] == sigs["o4"], f"{alg}#{i} firma determinista o3≠o4")
    chk(sig_c == sigs["o3"] or cr.public_key().verify(sig_c, msg) is None, f"{alg}#{i} firma cryptography no verifica")
    for n, exe in O.items():                                                 # exporta la clave pública de cada implementación para verificar en cruzado
        run(exe, "pkey", "-in", keys[n], "-pubout", "-out", f"{tmp}/pub_{n}.pem")
    # verificación cruzada y negativa
    bad_msg = msg + b"\x00" if rng.random() < .5 else (bytes([msg[0] ^ 1]) + msg[1:] if msg else b"\x01")
    bad_sig = bytearray(sigs["o3"]); bad_sig[rng.randrange(len(bad_sig))] ^= 1 << rng.randrange(8); bad_sig = bytes(bad_sig)
    for dst, exe in O.items():
        for label, sg, mm, ok in (("ok", sigs["o3"], msg, True), ("msg-alterado", sigs["o3"], bad_msg, False), ("firma-alterada", bad_sig, msg, False)):
            open(f"{tmp}/s2", "wb").write(sg); open(f"{tmp}/m2", "wb").write(mm)
            r = run(exe, "pkeyutl", "-verify", "-pubin", "-inkey", f"{tmp}/pub_{dst}.pem", "-in", f"{tmp}/m2", "-rawin", "-sigfile", f"{tmp}/s2")
            chk((r.returncode == 0) == ok, f"{alg}#{i} verificar {label} en {dst}")
    for label, sg, mm, ok in (("ok", sigs["o3"], msg, True), ("msg-alterado", sigs["o3"], bad_msg, False), ("firma-alterada", bad_sig, msg, False)):
        try:
            cr.public_key().verify(sg, mm); got = True
        except InvalidSignature:
            got = False
        chk(got == ok, f"{alg}#{i} verificar {label} en cryptography")


for i in range(N):
    kem_case("ML-KEM-768", mlkem.MLKEM768PrivateKey, i)
    kem_case("ML-KEM-1024", mlkem.MLKEM1024PrivateKey, i)
    for alg, cls in (("ML-DSA-44", mldsa.MLDSA44PrivateKey), ("ML-DSA-65", mldsa.MLDSA65PrivateKey), ("ML-DSA-87", mldsa.MLDSA87PrivateKey)):
        dsa_case(alg, cls, i)
print(f"casos por algoritmo: {N}; comprobaciones: {checks}; discrepancias: {len(fails)}")
for f in fails[:25]:
    print("  DIF:", f)
