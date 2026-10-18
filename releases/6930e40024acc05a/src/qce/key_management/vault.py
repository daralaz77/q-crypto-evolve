"""Persistencia cifrada del KeyStore (laboratorio). En producción: KMS/HSM vía `KeyBackend`.

Formato: cabecera(magic, versión, epoch, salt, n) autenticada como AAD + ChaCha20-Poly1305.
KDF: scrypt. El `epoch` creciente permite rechazar la restauración de un estado antiguo
(p. ej. volver a una copia donde una clave revocada seguía activa).
"""
from __future__ import annotations

import json
import os
import struct
import tempfile
from pathlib import Path
from typing import Protocol

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from ..core.errors import AuthenticationFailure, IntegrityError
from .keystore import KeyRecord, KeyStore, Purpose, State

MAGIC = b"QCEV"
VERSION = 1
SCRYPT_N = 2**15


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
    p = Path(path)
    fd, tmp = tempfile.mkstemp(dir=p.parent, prefix=".vault-")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(blob)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, p)  # escritura atómica
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def load(path: str | Path, passphrase: str, min_epoch: int = 0, **store_kwargs) -> KeyStore:
    data = Path(path).read_bytes()
    hlen = 4 + 13 + 16 + 12
    if len(data) < hlen + 16 or data[:4] != MAGIC:
        raise IntegrityError("vault inválido")
    version, epoch, n = struct.unpack(">BQI", data[4:17])
    if version != VERSION or n < 2**14 or n > 2**22:  # parámetros KDF no degradables
        raise IntegrityError("versión o parámetros KDF no admitidos")
    salt, nonce, header = data[17:33], data[33:45], data[:45]
    try:
        payload = ChaCha20Poly1305(_kdf(passphrase.encode(), salt, n)).decrypt(nonce, data[45:], header)
    except InvalidTag as exc:
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
