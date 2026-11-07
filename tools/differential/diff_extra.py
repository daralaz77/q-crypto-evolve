"""Prueba diferencial AMPLIADA: `cryptography` (OpenSSL) frente a una implementación independiente en Python puro (kyber-py / dilithium-py), en la MISMA ejecución.

Cubre lo que `diff_pqc.py` y `diff_pure.py` dejaban fuera: mensaje vacío y mensajes largos en ML-DSA, cadena de contexto (0, 1, 255 y 256 bytes), firmas con aleatoriedad (hedged),
contexto equivocado, firmas mal formadas (truncadas, vacías, de longitud errónea), semillas límite de ML-KEM, textos cifrados totalmente aleatorios (rechazo implícito) y claves
de encapsulación fuera de rango. Requiere `kyber-py`, `dilithium-py` y `cryptography` en el MISMO entorno aparte (no son dependencias del proyecto).
Uso: python diff_extra.py [casos] [control]    — `control` corrompe a propósito un lado: el arnés DEBE reportar discrepancias."""
import random
import sys

import dilithium_py.ml_dsa as D
import kyber_py.ml_kem as K
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import mldsa, mlkem

N = int(sys.argv[1]) if len(sys.argv) > 1 else 20
CONTROL = len(sys.argv) > 2 and sys.argv[2] == "control"
rng = random.Random(20261108)
fails, checks = [], 0
Q = 3329


def chk(cond, what):
    global checks
    checks += 1
    if not cond:
        fails.append(what)


def rb(n):
    return bytes(rng.randrange(256) for _ in range(n))


def c_verify(pub, sig, msg, ctx=b""):
    try:
        pub.verify(sig, msg, ctx)
        return True
    except (InvalidSignature, ValueError):
        return False


def c_sign(priv, msg, ctx=b""):
    try:
        return priv.sign(msg, ctx)
    except ValueError:
        return None


def p_sign(impl, sk, msg, ctx=b"", det=False):
    try:
        return impl.sign(sk, msg, ctx=ctx, deterministic=det)
    except (ValueError, AssertionError):
        return None


def p_verify(impl, pk, msg, sig, ctx=b""):
    try:
        return bool(impl.verify(pk, msg, sig, ctx=ctx))
    except (ValueError, AssertionError):
        return False


def dsa(alg, ccls, impl, i):
    seed = rb(32)
    pseed = bytes([seed[0] ^ 1]) + seed[1:] if CONTROL else seed
    cpriv = ccls.from_seed_bytes(seed)
    cpub = cpriv.public_key()
    pk, sk = impl.key_derive(pseed)
    chk(cpub.public_bytes_raw() == pk, f"{alg}#{i} clave pública")
    for mlen in (0, 1, 31, 32, 33, 1000, 100_000):
        msg = rb(mlen)
        for clen in (0, 1, 7, 255):
            ctx = rb(clen)
            sc, sp = c_sign(cpriv, msg, ctx), p_sign(impl, sk, msg, ctx)            # ambas con aleatoriedad (hedged)
            chk(sc is not None and sp is not None, f"{alg}#{i} firmar len={mlen} ctx={clen}")
            if sc is None or sp is None:
                continue
            chk(c_verify(cpub, sp, msg, ctx), f"{alg}#{i} cryptography verifica firma pura len={mlen} ctx={clen}")
            chk(p_verify(impl, pk, msg, sc, ctx), f"{alg}#{i} pura verifica firma cryptography len={mlen} ctx={clen}")
            wrong = ctx + b"\x01" if clen < 255 else ctx[:-1]
            chk(not c_verify(cpub, sp, msg, wrong) and not p_verify(impl, pk, msg, sp, wrong), f"{alg}#{i} contexto equivocado se acepta len={mlen} ctx={clen}")
            if mlen:
                bad = bytes([msg[0] ^ 1]) + msg[1:]
                chk(not c_verify(cpub, sc, bad, ctx) and not p_verify(impl, pk, bad, sc, ctx), f"{alg}#{i} mensaje alterado se acepta")
    # contexto de 256 bytes: ambas deben negarse a firmar y a verificar
    chk(c_sign(cpriv, b"m", rb(256)) is None and p_sign(impl, sk, b"m", rb(256)) is None, f"{alg}#{i} contexto de 256 bytes se acepta al firmar")
    s = c_sign(cpriv, b"m")
    chk(not c_verify(cpub, s, b"m", rb(256)) and not p_verify(impl, pk, b"m", s, rb(256)), f"{alg}#{i} contexto de 256 bytes se acepta al verificar")
    # firmas mal formadas
    good = c_sign(cpriv, b"m")
    for label, sg in (("vacía", b""), ("truncada", good[:-1]), ("extendida", good + b"\x00"), ("ceros", bytes(len(good))), ("unos", b"\xff" * len(good)), ("aleatoria", rb(len(good)))):
        chk(not c_verify(cpub, sg, b"m") and not p_verify(impl, pk, b"m", sg), f"{alg}#{i} firma {label} se acepta")


def kem(alg, ccls, impl, i):
    seeds = [bytes(64), b"\xff" * 64, bytes([1]) + bytes(63), bytes(63) + bytes([128])] + [rb(64) for _ in range(3)]
    for seed in seeds:
        pseed = bytes([seed[0] ^ 1]) + seed[1:] if CONTROL else seed
        cpriv = ccls.from_seed_bytes(seed)
        ek, dk = impl.key_derive(pseed)
        chk(cpriv.public_key().public_bytes_raw() == ek, f"{alg}#{i} clave de encapsulación (semilla límite {seed[:2].hex()})")
        # texto cifrado totalmente aleatorio: el rechazo implícito debe coincidir
        for _ in range(3):
            ct = rb(len(impl.encaps(ek)[1]))
            chk(cpriv.decapsulate(ct) == impl.decaps(dk, ct), f"{alg}#{i} rechazo implícito con texto aleatorio")
        a, b = impl.encaps(ek)
        ss, ct = (a, b) if len(a) == 32 else (b, a)
        chk(cpriv.decapsulate(ct) == ss, f"{alg}#{i} desencapsular texto de la implementación pura")
        css, cct = cpriv.public_key().encapsulate()
        chk(impl.decaps(dk, cct) == css, f"{alg}#{i} la pura desencapsula texto de cryptography")
    # clave de encapsulación fuera de rango (coeficiente ≥ q): ambas deben rechazarla
    cpriv = ccls.from_seed_bytes(rb(64))
    ek = bytearray(cpriv.public_key().public_bytes_raw())
    ek[0], ek[1] = Q & 0xFF, (ek[1] & 0xF0) | (Q >> 8)                          # coeficiente 3329 = q
    try:
        (mlkem.MLKEM768PublicKey if alg == "ML-KEM-768" else mlkem.MLKEM1024PublicKey).from_public_bytes(bytes(ek))
        c_rej = False
    except ValueError:
        c_rej = True
    try:
        impl.encaps(bytes(ek))
        p_rej = False
    except (ValueError, AssertionError):
        p_rej = True
    chk(c_rej == p_rej, f"{alg}#{i} clave fuera de rango: cryptography {'rechaza' if c_rej else 'acepta'}, pura {'rechaza' if p_rej else 'acepta'}")


for i in range(N):
    for alg, ccls, impl in (("ML-DSA-44", mldsa.MLDSA44PrivateKey, D.ML_DSA_44), ("ML-DSA-65", mldsa.MLDSA65PrivateKey, D.ML_DSA_65), ("ML-DSA-87", mldsa.MLDSA87PrivateKey, D.ML_DSA_87)):
        dsa(alg, ccls, impl, i)
    for alg, ccls, impl in (("ML-KEM-768", mlkem.MLKEM768PrivateKey, K.ML_KEM_768), ("ML-KEM-1024", mlkem.MLKEM1024PrivateKey, K.ML_KEM_1024)):
        kem(alg, ccls, impl, i)
print(f"{'CONTROL ' if CONTROL else ''}casos: {N}; comprobaciones: {checks}; discrepancias: {len(fails)}")
for f in sorted(set(fails))[:15]:
    print("  DIF:", f)
