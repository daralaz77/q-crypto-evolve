"""Ciclo de vida de claves: GENERACIÓN → USO CONTROLADO → ROTACIÓN → REVOCACIÓN → DESTRUCCIÓN."""
from __future__ import annotations

import os
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from ..core.chainlog import ChainLog
from ..core.encoding import pack, unpack
from ..core.errors import AuthenticationFailure, KeyStateError
from ..symmetric.aead import hkdf


class State(str, Enum):
    GENERATED = "GENERATED"
    ACTIVE = "ACTIVE"
    RETIRED = "RETIRED"  # solo descifrar/verificar (periodo de gracia tras rotar)
    REVOKED = "REVOKED"  # ningún uso, nunca
    DESTROYED = "DESTROYED"


class Purpose(str, Enum):
    ENCRYPT = "ENCRYPT"  # KEK de cifrado de datos
    SIGN = "SIGN"
    KEM = "KEM"
    AUTH = "AUTH"  # MAC / autenticación


TRANSITIONS = {
    State.GENERATED: {State.ACTIVE, State.DESTROYED},
    State.ACTIVE: {State.RETIRED, State.REVOKED},
    State.RETIRED: {State.REVOKED, State.DESTROYED},
    State.REVOKED: {State.DESTROYED},
    State.DESTROYED: set(),
}

PRODUCE = {"protect", "sign", "encapsulate", "authenticate"}  # requieren ACTIVE y no caducada
CONSUME = {"unprotect", "verify", "decapsulate", "check"}  # admiten ACTIVE o RETIRED


@dataclass
class KeyRecord:
    key_id: str
    purpose: Purpose
    state: State
    created: float
    not_after: float
    generation: int
    secret: bytearray | None = field(default=None, repr=False)  # nunca se imprime ni se registra


class KeyStore:
    def __init__(self, audit: ChainLog | None = None, clock: Callable[[], float] = time.time) -> None:
        self._keys: dict[str, KeyRecord] = {}
        self._audit = audit
        self._clock = clock
        self.epoch = 0  # monótono: detecta restauración de estados antiguos

    # ---- auditoría ---------------------------------------------------------------
    def _log(self, event: str, key_id: str, **extra) -> None:
        self.epoch += 1
        if self._audit:
            self._audit.append({"event": event, "key_id": key_id, "epoch": self.epoch, **extra})

    # ---- ciclo de vida -----------------------------------------------------------
    def create(self, purpose: Purpose, ttl_s: float, secret: bytes | None = None, generation: int = 1) -> str:
        key_id = uuid.uuid4().hex[:16]
        now = self._clock()
        self._keys[key_id] = KeyRecord(key_id, purpose, State.GENERATED, now, now + ttl_s, generation,
                                       bytearray(secret if secret is not None else os.urandom(32)))
        self._log("create", key_id, purpose=purpose.value, generation=generation)
        return key_id

    def _move(self, key_id: str, new: State, event: str, **extra) -> KeyRecord:
        rec = self._get(key_id)
        if new not in TRANSITIONS[rec.state]:
            raise KeyStateError(f"transición ilegal {rec.state.value} → {new.value}")
        rec.state = new
        if new in (State.REVOKED, State.DESTROYED):
            self._zeroize(rec)  # una clave revocada ya no tiene uso legítimo
        self._log(event, key_id, to=new.value, **extra)
        return rec

    def activate(self, key_id: str) -> None:
        self._move(key_id, State.ACTIVE, "activate")

    def rotate(self, key_id: str, ttl_s: float) -> str:
        old = self._get(key_id)
        new_id = self.create(old.purpose, ttl_s, generation=old.generation + 1)
        self.activate(new_id)
        self._move(key_id, State.RETIRED, "rotate", successor=new_id)
        return new_id

    def revoke(self, key_id: str, reason: str) -> None:
        self._move(key_id, State.REVOKED, "revoke", reason=reason)

    def destroy(self, key_id: str) -> None:
        self._move(key_id, State.DESTROYED, "destroy")

    @staticmethod
    def _zeroize(rec: KeyRecord) -> None:
        # Mejor esfuerzo: Python puede haber copiado el secreto (GC, intern). Ver LIMITATIONS.md.
        if rec.secret is not None:
            for i in range(len(rec.secret)):
                rec.secret[i] = 0
            rec.secret = None

    # ---- acceso controlado -------------------------------------------------------
    def _get(self, key_id: str) -> KeyRecord:
        try:
            return self._keys[key_id]
        except KeyError:
            raise KeyStateError("clave inexistente") from None

    def use(self, key_id: str, purpose: Purpose, operation: str) -> bytes:
        rec = self._get(key_id)
        if rec.purpose is not purpose:
            self._log("misuse", key_id, operation=operation, wanted=purpose.value, actual=rec.purpose.value)
            raise KeyStateError("propósito de clave incorrecto (separación de claves)")
        if operation in PRODUCE:
            if rec.state is not State.ACTIVE:
                raise KeyStateError(f"no se puede {operation} con clave {rec.state.value}")
            if self._clock() >= rec.not_after:
                raise KeyStateError("clave caducada: rotar")
        elif operation in CONSUME:
            if rec.state not in (State.ACTIVE, State.RETIRED):
                raise KeyStateError(f"no se puede {operation} con clave {rec.state.value}")
        else:
            raise KeyStateError("operación desconocida")
        if rec.secret is None:
            raise KeyStateError("la clave no tiene material (destruida)")
        return bytes(rec.secret)

    def info(self, key_id: str) -> KeyRecord:
        return self._get(key_id)

    def all_ids(self) -> list[str]:
        return list(self._keys)

    # ---- cifrado de datos con sobre (cada mensaje usa una subclave de un solo uso) ----
    def protect(self, key_id: str, plaintext: bytes, aad: bytes = b"") -> bytes:
        kek = self.use(key_id, Purpose.ENCRYPT, "protect")
        rec = self._get(key_id)
        salt = os.urandom(32)
        sub = hkdf(kek, b"QCE1/dem/" + key_id.encode(), 32, salt)
        # subclave única por mensaje → nonce fijo es seguro (nunca se reutiliza clave+nonce)
        ct = ChaCha20Poly1305(sub).encrypt(b"\x00" * 12, plaintext, self._aad(key_id, rec.generation, aad))
        return pack(0x30, [key_id.encode(), rec.generation.to_bytes(4, "big"), salt, ct])

    def unprotect(self, blob: bytes, aad: bytes = b"") -> bytes:
        key_id_b, gen_b, salt, ct = unpack(blob, 0x30, 4)
        key_id = key_id_b.decode("ascii", "replace")
        kek = self.use(key_id, Purpose.ENCRYPT, "unprotect")
        gen = int.from_bytes(gen_b, "big")
        sub = hkdf(kek, b"QCE1/dem/" + key_id_b, 32, salt)
        try:
            return ChaCha20Poly1305(sub).decrypt(b"\x00" * 12, ct, self._aad(key_id, gen, aad))
        except Exception as exc:  # InvalidTag
            raise AuthenticationFailure("datos protegidos alterados o clave incorrecta") from exc

    @staticmethod
    def _aad(key_id: str, generation: int, aad: bytes) -> bytes:
        return key_id.encode() + generation.to_bytes(4, "big") + aad
