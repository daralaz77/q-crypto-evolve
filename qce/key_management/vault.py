"""Persistencia cifrada del KeyStore (laboratorio). En producción: KMS/HSM vía `KeyBackend`.

Formato: cabecera(magic, versión, epoch, salt, n) autenticada como AAD + ChaCha20-Poly1305.
KDF: scrypt. El `epoch` creciente permite rechazar la restauración de un estado antiguo
(p. ej. volver a una copia donde una clave revocada seguía activa).
"""
from __future__ import annotations

import fcntl
import json
import os
import struct
from pathlib import Path
from typing import Protocol

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from ..core.atomic import atomic_write
from ..core.errors import AuthenticationFailure, IntegrityError
from .keystore import KeyRecord, KeyStore, Purpose, State

MAGIC = b"QCEV"
VERSION = 1
SCRYPT_N = 2**15


class EpochAnchor:
    """Ancla del `epoch` MÍNIMO aceptable, guardada FUERA del vault (otro archivo, idealmente en otro medio). Sin ella, quien restaure una copia antigua del vault
    restaura también su `epoch` y la comprobación `epoch < min_epoch` se cumple a sí misma. Monótona: no admite retroceder, tampoco entre procesos que la
    adelantan a la vez (leer-comparar-reemplazar va bajo `flock`). Archivo 0600, escritura atómica."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def read(self) -> int:
        try:
            d = json.loads(self.path.read_text(encoding="utf-8"))
            n = d["epoch"]
            if not isinstance(n, int) or n < 0:
                raise ValueError
            return n
        except FileNotFoundError:
            return 0
        except (ValueError, KeyError, TypeError) as exc:  # ancla ilegible: NO se asume 0 (eso permitiría cualquier restauración)
            raise IntegrityError("el ancla de epoch está dañada") from exc

    def advance(self, epoch: int) -> None:
        with open(self.path.with_name(self.path.name + ".lock"), "w") as lk:
            fcntl.flock(lk, fcntl.LOCK_EX)
            if epoch < self.read():
                raise IntegrityError("el ancla de epoch no puede retroceder")
            atomic_write(self.path, json.dumps({"epoch": epoch}).encode(), prefix=".epoch-")


def save_anchored(store: KeyStore, path: str | Path, passphrase: str, anchor: EpochAnchor, n: int = SCRYPT_N) -> None:
    """Guarda el vault y, SOLO después, adelanta el ancla externa al `epoch` guardado."""
    save(store, path, passphrase, n)
    anchor.advance(store.epoch)


def load_anchored(path: str | Path, passphrase: str, anchor: EpochAnchor, **store_kwargs) -> KeyStore:
    """Carga exigiendo `epoch` >= el del ancla externa: una copia antigua del vault (con su epoch antiguo) se rechaza."""
    store = load(path, passphrase, min_epoch=anchor.read(), **store_kwargs)
    anchor.advance(store.epoch)
    return store


class KeyBackend(Protocol):
    """Interfaz para sustituir el vault por un KMS o HSM real."""

    def save(self, store: KeyStore) -> None: ...
    def load(self, min_epoch: int) -> KeyStore: ...


def _kdf(passphrase: bytes, salt: bytes, n: int) -> bytes:
    return Scrypt(salt=salt, length=32, n=n, r=8, p=1).derive(passphrase)


def save(store: KeyStore, path: str | Path, passphrase: str, n: int = SCRYPT_N) -> None:
    salt, nonce = os.urandom(16), os.urandom(12)
    header = MAGIC + struct.pack(">BQI", VERSION, store.epoch, n) + salt + nonce
    payload = json.dumps([{
        "key_id": r.key_id, "purpose": r.purpose.value, "state": r.state.value,
        "created": r.created, "not_after": r.not_after, "generation": r.generation,
        "secret": r.secret.hex() if r.secret is not None else None,
    } for r in (store.info(k) for k in store.all_ids())]).encode()
    blob = header + ChaCha20Poly1305(_kdf(passphrase.encode(), salt, n)).encrypt(nonce, payload, header)
    atomic_write(path, blob, prefix=".vault-")


def load(path: str | Path, passphrase: str, min_epoch: int = 0, **store_kwargs) -> KeyStore:
    data = Path(path).read_bytes()
    hlen = 4 + 13 + 16 + 12
    if len(data) < hlen + 16 or data[:4] != MAGIC:
        raise IntegrityError("vault inválido")
    version, epoch, n = struct.unpack(">BQI", data[4:17])
    if version != VERSION or n < 2**14 or n > 2**17 or n & (n - 1):  # no degradable ni inflable (DoS) antes de autenticar
        raise IntegrityError("versión o parámetros KDF no admitidos")
    salt, nonce, header = data[17:33], data[33:45], data[:45]
    try:
        payload = ChaCha20Poly1305(_kdf(passphrase.encode(), salt, n)).decrypt(nonce, data[45:], header)
    except (InvalidTag, ValueError) as exc:
        raise AuthenticationFailure("frase incorrecta o vault manipulado") from exc
    if epoch < min_epoch:
        raise IntegrityError(f"restauración de estado antiguo (epoch {epoch} < {min_epoch})")
    store = KeyStore(**store_kwargs)
    store.epoch = epoch
    for d in json.loads(payload):
        store._keys[d["key_id"]] = KeyRecord(
            d["key_id"], Purpose(d["purpose"]), State(d["state"]), d["created"], d["not_after"],
            d["generation"], bytearray.fromhex(d["secret"]) if d["secret"] else None)
    return store
