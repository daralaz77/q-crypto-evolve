"""Quien ENTREGA: el guardián de un candado y el custodio con diario.

Candado: quien rompiera las FIRMAS (justo el escenario que un candado simétrico quiere resistir) podría falsificar una cabecera y una solicitud. Por eso una ficha
exige todo esto, y lo tres últimos solo dependen de criptografía simétrica:

  1. archivo (o resguardo) íntegro y solicitud firmada, vigente y de un solicitante listado en la cabecera;
  2. el archivo fue REGISTRADO por el guardián al sellarlo (huella de la cabecera) y no se ha retirado;
  3. el solicitante está dado de ALTA y acompaña una prueba HMAC con un secreto que se le entregó por un canal propio;
  4. esa solicitud no se ha atendido antes.

La ficha es SECRETA y va en claro a propósito: cifrarla para quien abre con clave pública volvería a dejar el candado a merced de quien la rompa. Transportarla por un
canal que no dependa de ella y destruirla tras usarla. La entrega se anota ANTES de devolver nada: si no se puede anotar, no se entrega.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time
from collections.abc import Callable
from pathlib import Path

from ..core.encoding import lp
from ..core.errors import AuthenticationFailure, PolicyViolation
from ..symmetric.aead import ct_equal, hkdf
from . import envelope
from .journal import Journal

KEEPER_EVENTS = {"register": {"file"}, "withdraw": {"file"}, "enroll": {"requester"}, "revoke": {"requester"},
                 "deliver": {"request", "file", "requester", "expires", "reason"}}
CUSTODIAN_EVENTS = {"serve": {"request", "file", "requester", "expires", "reason"}}


def prove(request_id: bytes, secret: bytes) -> bytes:
    """La calcula el SOLICITANTE con el secreto que el guardián le entregó en el alta. `request_id` = `envelope.read_request(...).ident`."""
    return hmac.new(secret, lp(b"QSEL3/keeper-proof") + lp(request_id), hashlib.sha256).digest()


class Keeper:
    def __init__(self, lock: envelope.Lock, journal: str | Path, clock: Callable[[], float] = time.time, anchor: str | Path | None = None,
                 pinned_head: tuple[int, bytes] | None = None) -> None:
        self.lock, self._clock = lock, clock
        key = hkdf(lock.key, lp(b"QSEL3/keeper-journal") + lp(lock.ident))
        self.journal = Journal(journal, key, KEEPER_EVENTS, clock, anchor, pinned_head)

    @staticmethod
    def _state(entries: list[dict]) -> tuple[dict[str, bool], dict[str, bool], set[str]]:
        """(archivos → ¿activo?, solicitantes → ¿de alta?, solicitudes ya atendidas)."""
        files: dict[str, bool] = {}
        requesters: dict[str, bool] = {}
        delivered: set[str] = set()
        for e in entries:
            kind, data = e["type"], e["data"]
            if kind in ("register", "withdraw"):
                files[data["file"]] = kind == "register"
            elif kind in ("enroll", "revoke"):
                requesters[data["requester"]] = kind == "enroll"
            else:
                delivered.add(data["request"])
        return files, requesters, delivered

    def _file_key(self, hd: envelope.Header) -> bytes:
        """La clave de ESTE archivo, si el archivo exige este candado y la maestra es la que lo cierra."""
        entry = next((k for k in hd.data["locks"] if k["id"] == self.lock.ident.hex()), None)
        if entry is None:
            raise PolicyViolation("este candado no es de este archivo")
        sid = bytes.fromhex(hd.data["sid"])
        file_key = self.lock.file_key(sid)
        if not ct_equal(bytes.fromhex(entry["com"]), bytes.fromhex(envelope._lock_commitment(sid, self.lock.ident, file_key))):
            raise AuthenticationFailure("la clave del candado no es la que cierra este archivo")
        return file_key

    def register(self, path: str | Path, sender_public: bytes) -> str:
        """Hacerlo AL SELLAR, mientras las firmas son de fiar y con el archivo recibido de primera mano. Un archivo retirado no se vuelve a registrar."""
        hd, _, _ = envelope.verify_file(path, sender_public)
        self._file_key(hd)
        name = hd.digest.hex()
        with self.journal.transaction() as (entries, append):
            files = self._state(entries)[0]
            if name in files:
                raise PolicyViolation("ese archivo ya está registrado" if files[name] else "ese archivo fue RETIRADO: no se vuelve a registrar")
            append("register", {"file": name})
        return name

    def withdraw(self, file: str) -> None:
        """Retira UN archivo sin destruir la maestra: no habrá fichas nuevas para él (las ya emitidas siguen valiendo)."""
        with self.journal.transaction() as (entries, append):
            if not self._state(entries)[0].get(file):
                raise PolicyViolation("ese archivo no está registrado y activo")
            append("withdraw", {"file": file})

    def requester_secret(self, requester: str) -> bytes:
        return hkdf(self.lock.key, lp(b"QSEL3/keeper-requester") + lp(self.lock.ident) + lp(bytes.fromhex(requester)))

    def enroll(self, requester_public: bytes) -> bytes:
        """Da de alta a un solicitante y devuelve SU secreto (entregarlo por un canal que no dependa de clave pública). Una baja es definitiva."""
        who = envelope.fingerprint(requester_public)
        with self.journal.transaction() as (entries, append):
            requesters = self._state(entries)[1]
            if who in requesters:
                raise PolicyViolation("ya está dado de alta" if requesters[who] else "fue dado de BAJA: genera una clave de firma nueva")
            append("enroll", {"requester": who})
        return self.requester_secret(who)

    def revoke(self, requester_public: bytes) -> None:
        who = envelope.fingerprint(requester_public)
        with self.journal.transaction() as (entries, append):
            if not self._state(entries)[1].get(who):
                raise PolicyViolation("ese solicitante no está de alta")
            append("revoke", {"requester": who})

    def release(self, path: str | Path, sender_public: bytes, request: bytes, proof: bytes) -> bytes:
        """Emite la FICHA de un archivo."""
        hd, _, _ = envelope.verify_file(path, sender_public)
        req = envelope.read_request(hd, request, int(self._clock()))
        file_key = self._file_key(hd)
        name = hd.digest.hex()
        with self.journal.transaction() as (entries, append):
            files, requesters, delivered = self._state(entries)
            if not files.get(name):
                raise PolicyViolation("archivo NO registrado por el guardián (o retirado)")
            if not requesters.get(req.requester):
                raise PolicyViolation("solicitante sin alta en el guardián (o dado de baja)")
            if not ct_equal(proof, prove(req.ident, self.requester_secret(req.requester))):
                raise AuthenticationFailure("prueba simétrica del solicitante inválida")
            if req.ident.hex() in delivered:
                raise PolicyViolation("esa solicitud YA se atendió: pide una nueva")
            append("deliver", {"request": req.ident.hex(), "file": name, "requester": req.requester, "expires": req.expires, "reason": req.reason})
        return json.dumps({"v": 3, "file": name, "id": self.lock.ident.hex(), "key": envelope._b64(file_key)}, sort_keys=True).encode()

    def deliveries(self) -> list[dict]:
        return [e["data"] for e in self.journal.read() if e["type"] == "deliver"]


class Custodian:
    """Un custodio CON MEMORIA: atiende cada solicitud una sola vez y deja constancia. `envelope.contribute` es la primitiva sin memoria."""

    def __init__(self, key, journal: str | Path, clock: Callable[[], float] = time.time, anchor: str | Path | None = None,
                 pinned_head: tuple[int, bytes] | None = None) -> None:
        self.key, self._clock = key, clock
        journal_key = hkdf(key.seed(), lp(b"QSEL3/custodian-journal"))
        self.journal = Journal(journal, journal_key, CUSTODIAN_EVENTS, clock, anchor, pinned_head)

    def contribute(self, path: str | Path, sender_public: bytes, request: bytes) -> bytes:
        now = int(self._clock())
        hd, _, _ = envelope.verify_file(path, sender_public)
        req = envelope.read_request(hd, request, now)
        with self.journal.transaction() as (entries, append):
            if any(e["data"]["request"] == req.ident.hex() for e in entries):
                raise PolicyViolation("esa solicitud YA se atendió: pide una nueva")
            part = envelope.contribute(path, sender_public, self.key, request, now)  # si falla (no es custodio, archivo distinto) no se anota
            append("serve", {"request": req.ident.hex(), "file": hd.digest.hex(), "requester": req.requester, "expires": req.expires, "reason": req.reason})
        return part

    def served(self) -> list[dict]:
        return [e["data"] for e in self.journal.read()]
