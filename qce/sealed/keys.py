"""Archivos de clave del sobre sellado: los secretos van SIEMPRE cifrados con una frase (scrypt + ChaCha20-Poly1305, como el vault); las públicas declaran su algoritmo.

Todo lo que no es el secreto (tipo, nivel, algoritmo, datos del candado, parámetros de scrypt) va en claro pero AUTENTICADO: cambiarlo impide abrir.
LÍMITE: una frase débil se puede probar sin conexión; en memoria, Python no borra los secretos.
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from ..core.atomic import atomic_write
from ..core.errors import AuthenticationFailure, MalformedMessage, PolicyViolation
from ..pqc.hybrid import LEVELS
from .envelope import SUITES, _b64, _keys, _strict_json, _unb64

SCRYPT_N = 2**15
MIN_PASSPHRASE = 12
EMISOR, CUSTODIO = "emisor", "custodio"                      # tipos con clave pública
SECRET_KINDS = (EMISOR, CUSTODIO, "candado", "parte", "secreto")


def algorithm(kind: str, level: str) -> str:
    if kind == EMISOR:
        return f"Ed25519+ML-DSA ({level})"
    if kind == CUSTODIO:
        return SUITES[level].kem
    return "simétrico-256"


def random_passphrase() -> str:
    """128 bits al azar (base32 en grupos de cinco): quien robe el archivo de clave no puede probarla sin conexión."""
    text = base64.b32encode(os.urandom(16)).decode().rstrip("=")
    return "-".join(text[i : i + 5] for i in range(0, len(text), 5))


def _kdf(passphrase: str, salt: bytes, n: int) -> bytes:
    return Scrypt(salt=salt, length=32, n=n, r=8, p=1).derive(passphrase.encode("utf-8"))


def _canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _new_file(path: Path) -> None:
    if path.exists():
        raise PolicyViolation(f"{path} ya existe: no se sobrescribe una clave")


def save_secret(path: str | Path, kind: str, secret: bytes, passphrase: str, level: str = "", extra: dict | None = None, n: int = SCRYPT_N) -> None:
    if kind not in SECRET_KINDS:
        raise PolicyViolation("tipo de secreto desconocido")
    if len(passphrase) < MIN_PASSPHRASE:
        raise PolicyViolation(f"la frase debe tener al menos {MIN_PASSPHRASE} caracteres")
    path = Path(path)
    _new_file(path)
    salt, nonce = os.urandom(16), os.urandom(12)
    meta = {"v": 1, "kind": kind, "level": level, "algorithm": algorithm(kind, level), "extra": extra or {}, "n": n, "salt": _b64(salt), "nonce": _b64(nonce)}
    box = ChaCha20Poly1305(_kdf(passphrase, salt, n)).encrypt(nonce, secret, _canonical(meta))
    atomic_write(path, _canonical({**meta, "box": _b64(box)}), 0o600)


def load_secret(path: str | Path, kind: str, passphrase: str) -> tuple[dict, bytes]:
    obj = _keys(_strict_json(Path(path).read_bytes()), {"v", "kind", "level", "algorithm", "extra", "n", "salt", "nonce", "box"})
    n = obj["n"]
    if type(obj["v"]) is not int or obj["v"] != 1 or type(n) is not int or n < 2**14 or n > 2**17 or n & (n - 1):  # ni degradable ni inflable (DoS)
        raise MalformedMessage("versión o parámetros de derivación no admitidos")
    if obj["kind"] != kind:
        raise PolicyViolation(f"{path}: es una clave de otro tipo (se esperaba «{kind}»)")
    if not isinstance(obj["box"], str) or not isinstance(obj["extra"], dict):
        raise MalformedMessage("archivo de clave mal formado")
    meta = {k: v for k, v in obj.items() if k != "box"}
    salt, nonce = _unb64(obj["salt"], 16), _unb64(obj["nonce"], 12)
    try:
        box = _unb64(obj["box"], (len(obj["box"]) // 4) * 3 - obj["box"][-2:].count("="))
        secret = ChaCha20Poly1305(_kdf(passphrase, salt, n)).decrypt(nonce, box, _canonical(meta))
    except (InvalidTag, ValueError) as exc:
        raise AuthenticationFailure("frase incorrecta o archivo de clave manipulado") from exc
    return meta, secret


def save_public(path: str | Path, kind: str, level: str, public: bytes) -> None:
    path = Path(path)
    _new_file(path)
    atomic_write(path, _canonical({"kind": kind, "level": level, "algorithm": algorithm(kind, level), "public": public.hex()}), 0o644)


def load_public(path: str | Path, kind: str) -> bytes:
    """X-Wing y el híbrido estándar de QCE miden lo mismo: la clave declara su algoritmo para no sellar nunca un archivo imposible de abrir."""
    d = _keys(_strict_json(Path(path).read_bytes()), {"kind", "level", "algorithm", "public"})
    if d["kind"] != kind or d["level"] not in LEVELS or d["algorithm"] != algorithm(kind, d["level"]):
        raise PolicyViolation(f"{path}: se esperaba una clave pública de tipo «{kind}» de esta versión")
    try:
        return bytes.fromhex(d["public"])
    except (TypeError, ValueError) as exc:
        raise MalformedMessage("clave pública ilegible") from exc
