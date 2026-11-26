"""Definición de los vectores del sobre sellado. NO se guarda ningún secreto: todas las claves salen de etiquetas (SHAKE256) y los valores intermedios esperados
se publican como huellas truncadas de SHA-256. `tools/sealed_vectors.py` genera los archivos; las pruebas usan los guardados."""
import hashlib

ISSUED = 1_900_000_000                     # instante fijo de las solicitudes
CASES = [
    {"name": "v1-estandar-minimo", "level": "standard", "aead": "AES-256-GCM", "plain_len": 4, "need": 1, "groups": [("unico", 1, 1)], "quorum": [(1, 1)], "locks": []},
    {"name": "v2-estandar-dos-grupos", "level": "standard", "aead": "CHACHA20-POLY1305", "plain_len": 70000, "need": 2,
     "groups": [("direccion", 2, 3), ("legal", 1, 2)], "quorum": [(1, 1), (1, 3), (2, 2)], "locks": []},
    {"name": "v3-alto-umbral-de-grupos", "level": "high", "aead": "AES-256-GCM", "plain_len": 100, "need": 1,
     "groups": [("solo", 1, 1), ("pareja", 2, 2)], "quorum": [(2, 1), (2, 2)], "locks": []},
    {"name": "v4-estandar-dos-candados", "level": "standard", "aead": "AES-256-GCM", "plain_len": 300, "need": 1,
     "groups": [("unico", 1, 2)], "quorum": [(1, 2)], "locks": ["caja-fuerte", "plazo-2031"]},
]


def derive(case: str, role: str, n: int) -> bytes:
    return hashlib.shake_256(f"qsello-vector-v3/{case}/{role}".encode()).digest(n)


def kem_seed_length(level: str) -> int:
    return 32 if level == "standard" else 96


def short(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()[:16]


def plaintext(n: int) -> bytes:
    return bytes(i % 251 for i in range(n))
