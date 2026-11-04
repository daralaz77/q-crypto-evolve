"""Prueba estadística de tiempo (estilo dudect) de las operaciones con secretos. Cierra PARCIALMENTE la brecha B8 de docs/COMPARATIVA_PQC.md.

Método (Reparaz, Balasch, Verbauwhede, «Dude, is my code constant time?», 2016; reescrito aquí, no copiado): dos clases de entrada, una FIJA y otra ALEATORIA,
intercaladas al azar; se mide cada llamada con `perf_counter_ns`, se descartan las colas altas (ruido del sistema) y se compara con una prueba t de Welch.
|t| > 4,5 es evidencia fuerte de que el tiempo depende de la entrada.

  python tools/timing_check.py                 # todas las pruebas, 20 000 muestras por clase
  python tools/timing_check.py --samples 50000 --only canary-naive,ct_equal

Cada serie incluye un CANARIO: una comparación ingenua con salida temprana DEBE salir con fuga (si no, el instrumento no sirve y la prueba falla; es la misma idea que el
canario del arnés de mutación). Sale con 1 si el canario no se detecta o si una operación real supera el umbral de forma repetida.

LÍMITES (importantes): (1) esto mide Python + OpenSSL en ESTA máquina, no la implementación en otro compilador o CPU; (2) que no se detecte fuga NO prueba
tiempo constante (solo que no se vio con N muestras); (3) no mide consumo, caché ni emisiones; (4) un |t| alto puede ser ruido del sistema: por eso se repite
la medición y solo se marca «fuga» si supera el umbral en TODAS las repeticiones. No sustituye a ctgrind/ct-verif ni a la revisión humana."""
from __future__ import annotations

import argparse
import hmac
import math
import os
import random
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

THRESHOLD = 4.5
REPEATS = 3


def welch_t(a: list[int], b: list[int]) -> float:
    na, nb = len(a), len(b)
    ma, mb = sum(a) / na, sum(b) / nb
    va = sum((x - ma) ** 2 for x in a) / (na - 1)
    vb = sum((x - mb) ** 2 for x in b) / (nb - 1)
    den = math.sqrt(va / na + vb / nb)
    return 0.0 if den == 0 else (ma - mb) / den


def crop(xs: list[int], pct: float = 0.9) -> list[int]:
    cut = sorted(xs)[int(len(xs) * pct)]
    return [x for x in xs if x <= cut]


def measure(fn, fixed, randoms, n: int) -> float:
    """Intercala llamadas con la entrada fija (clase 0) y aleatorias (clase 1); devuelve |t| tras recortar el 10 % más lento de cada clase.
    La clase fija usa un grupo de COPIAS (mismo contenido, objetos distintos): si fuera siempre el mismo objeto, el caché y el predictor de saltos lo
    favorecerían y la prueba mediría eso en vez de la dependencia del dato (artefacto que en Python aparece con facilidad)."""
    order = [random.getrandbits(1) for _ in range(n * 2)]
    fixed_pool = [bytes(bytearray(fixed)) for _ in range(len(randoms))]
    t0: list[int] = []
    t1: list[int] = []
    ri = fi = 0
    for c in order:
        if c == 0:
            arg = fixed_pool[fi % len(fixed_pool)]
            fi += 1
        else:
            arg = randoms[ri % len(randoms)]
            ri += 1
        s = time.perf_counter_ns()
        fn(arg)
        e = time.perf_counter_ns()
        (t0 if c == 0 else t1).append(e - s)
    return abs(welch_t(crop(t0), crop(t1)))


def targets():
    from qce.pqc.hybrid import STANDARD, HybridKemPrivateKey, hybrid_encapsulate

    secret = os.urandom(64)
    naive_guess = bytearray(secret)  # misma longitud; difiere pronto en la clase aleatoria, no en la fija

    def naive(guess: bytes) -> bool:
        for a, b in zip(guess, secret):  # el canario: bucle con salida temprana (el tipo de comparación que esta prueba DEBE cazar)
            if a != b:
                return False
        return True

    def ct_eq(guess: bytes) -> bool:
        return hmac.compare_digest(guess, secret)

    yield "canary-naive", naive, bytes(naive_guess), [os.urandom(64) for _ in range(512)], True
    yield "ct_equal", ct_eq, bytes(naive_guess), [os.urandom(64) for _ in range(512)], False

    sk = HybridKemPrivateKey.generate(STANDARD)
    ss, ct = hybrid_encapsulate(sk.public_bytes, STANDARD)
    rnd = [os.urandom(len(ct)) for _ in range(512)]  # X25519 acepta cualquier punto; ML-KEM rechaza de forma implícita
    yield "hybrid-decapsulate", sk.decapsulate, ct, rnd, False

    # El mismo ct con SOLO una mitad variable: separa qué componente aporta la diferencia de tiempo (X25519 o ML-KEM) y cuál solo mide la entrada.
    yield "hybrid-vary-x25519-half", sk.decapsulate, ct, [os.urandom(32) + ct[32:] for _ in range(512)], False
    yield "hybrid-vary-mlkem-half", sk.decapsulate, ct, [ct[:32] + os.urandom(len(ct) - 32) for _ in range(512)], False

    from cryptography.hazmat.primitives.asymmetric import mlkem, x25519
    xk = x25519.X25519PrivateKey.generate()
    xp = x25519.X25519PrivateKey.generate().public_key()
    xpub = xp.public_bytes_raw()
    yield "x25519-exchange", lambda b: xk.exchange(x25519.X25519PublicKey.from_public_bytes(b)), xpub, [
        x25519.X25519PrivateKey.generate().public_key().public_bytes_raw() for _ in range(512)], False
    m = mlkem.MLKEM768PrivateKey.generate()
    _, ct_m = m.public_key().encapsulate()
    yield "mlkem768-decapsulate", m.decapsulate, ct_m, [os.urandom(len(ct_m)) for _ in range(512)], False


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--samples", type=int, default=20000, help="llamadas por clase y repetición")
    ap.add_argument("--only", default="", help="nombres separados por comas")
    args = ap.parse_args()
    only = {x for x in args.only.split(",") if x}
    bad = False
    print(f"umbral |t| > {THRESHOLD}; {REPEATS} repeticiones; {args.samples} muestras por clase\n")
    for name, fn, fixed, randoms, canary in targets():
        if only and name not in only:
            continue
        for _ in range(200):  # calentamiento
            fn(fixed)
        ts = [measure(fn, fixed, randoms, args.samples) for _ in range(REPEATS)]
        leak = all(t > THRESHOLD for t in ts)
        verdict = ("FUGA DETECTADA" if leak else "sin fuga detectada")
        if canary:
            verdict += "  (esperado: el instrumento funciona)" if leak else "  ← EL CANARIO NO SE DETECTÓ: la medición no es fiable"
            bad |= not leak
        else:
            bad |= leak
        print(f"{name:24s} |t| = {', '.join(f'{t:6.2f}' for t in ts)}  →  {verdict}")
    print("\n«sin fuga detectada» no prueba tiempo constante; ver los límites en el encabezado de este archivo.")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
