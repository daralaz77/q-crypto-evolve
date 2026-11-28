"""Quien ENTREGA: el guardián de un candado y el custodio con diario.

Candado: quien rompiera las FIRMAS (justo el escenario que un candado simétrico quiere resistir) podría falsificar una cabecera y una solicitud. Por eso una ficha
exige todo esto, y lo tres últimos solo dependen de criptografía simétrica:

  1. archivo (o resguardo) íntegro y solicitud firmada, vigente y de un solicitante listado en la cabecera;
  2. el archivo fue REGISTRADO por el guardián al sellarlo (huella de la cabecera) y no se ha retirado;
  3. el solicitante está dado de ALTA y acompaña una prueba HMAC con un secreto que se le entregó por un canal propio;
  4. esa solicitud no se ha atendido antes ni caducó antes del último apunte del diario (aunque el reloj diga otra cosa).

Un custodio con diario puede además RETIRAR un archivo (p. ej. tras volver a sellarlo sin quien dejó de ser custodio): no volverá a participar en abrirlo.

Retirar se hace por el `sid` del archivo y no solo por la huella de su cabecera: las participaciones van atadas al `sid`, y quien pueda firmar como el emisor podría
reescribir la misma cabecera con otros bytes (otra huella) sin que las participaciones dejen de abrirse.

La ficha es SECRETA y va en claro a propósito: cifrarla para quien abre con clave pública volvería a dejar el candado a merced de quien la rompa. Transportarla por un
canal que no dependa de ella y destruirla tras usarla. La entrega se anota ANTES de devolver nada: si no se puede anotar, no se entrega.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time
from collections.abc import Callable, Sequence
from pathlib import Path

from ..core.encoding import lp
from ..core.errors import AuthenticationFailure, PolicyViolation
from ..symmetric.aead import ct_equal, hkdf
from . import envelope
from .journal import Journal

KEEPER_EVENTS = {"register": {"file"}, "withdraw": {"file"}, "enroll": {"requester"}, "revoke": {"requester"},
                 "deliver": {"request", "file", "requester", "expires", "reason"}, "bar": {"sid"}, "tick": set()}
CUSTODIAN_EVENTS = {"serve": {"request", "file", "requester", "expires", "reason"}, "withdraw": {"sid"}, "tick": set()}
Anchors = str | Path | Sequence[str | Path] | None


def prove(request_id: bytes, secret: bytes) -> bytes:
    """La calcula el SOLICITANTE con el secreto que el guardián le entregó en el alta. `request_id` = `envelope.read_request(...).ident`."""
    return hmac.new(secret, lp(b"QSEL3/keeper-proof") + lp(request_id), hashlib.sha256).digest()


def _not_before_journal(req: envelope.Request, entries: list[dict]) -> None:
    """El diario es un segundo reloj que no retrocede: retrasar el del equipo no revive lo que ya había caducado cuando se anotó el último apunte."""
    if req.expires < max((e["data"]["at"] for e in entries), default=0):
        raise PolicyViolation("la solicitud ya había CADUCADO según el diario (¿reloj retrasado?)")


def _identifier(value: str) -> None:
    if len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise PolicyViolation("identificador de archivo inválido")


class Keeper:
    def __init__(self, lock: envelope.Lock, journal: str | Path, clock: Callable[[], float] = time.time, anchor: Anchors = None,
                 pinned_head: tuple[int, bytes] | None = None) -> None:
        self.lock, self._clock = lock, clock
        key = hkdf(lock.key, lp(b"QSEL3/keeper-journal") + lp(lock.ident))
        self.journal = Journal(journal, key, KEEPER_EVENTS, clock, anchor, pinned_head)

    @staticmethod
    def _state(entries: list[dict]) -> tuple[dict[str, bool], dict[str, bool], set[str], set[str]]:
        """(archivos → ¿activo?, solicitantes → ¿de alta?, solicitudes ya atendidas, `sid` retirados)."""
        files: dict[str, bool] = {}
        requesters: dict[str, bool] = {}
        delivered: set[str] = set()
        barred: set[str] = set()
        for e in entries:
            kind, data = e["type"], e["data"]
            if kind in ("register", "withdraw"):
                files[data["file"]] = kind == "register"
            elif kind in ("enroll", "revoke"):
                requesters[data["requester"]] = kind == "enroll"
            elif kind == "deliver":
                delivered.add(data["request"])
            elif kind == "bar":
                barred.add(data["sid"])
        return files, requesters, delivered, barred

    def _file_key(self, hd: envelope.Header) -> tuple[dict, bytes]:
        """(entrada de la cabecera, clave de ESTE archivo), si el archivo exige este candado y la maestra es la que lo cierra."""
        sid = bytes.fromhex(hd.data["sid"])
        ident = envelope.lock_header_id(hd.hidden, sid, self.lock.ident)
        entry = next((k for k in hd.data["locks"] if k["id"] == ident), None)
        if entry is None:
            raise PolicyViolation("este candado no es de este archivo")
        file_key = self.lock.file_key(sid)
        if not ct_equal(bytes.fromhex(entry["com"]), bytes.fromhex(envelope._lock_commitment(sid, bytes.fromhex(ident), file_key))):
            raise AuthenticationFailure("la clave del candado no es la que cierra este archivo")
        return entry, file_key

    def register(self, path: str | Path, sender_public: bytes) -> str:
        """Hacerlo AL SELLAR, mientras las firmas son de fiar y con el archivo recibido de primera mano. Un archivo retirado no se vuelve a registrar."""
        hd, _, _ = envelope.verify_file(path, sender_public)
        self._file_key(hd)
        name = hd.digest.hex()
        with self.journal.transaction() as (entries, append):
            files, _, _, barred = self._state(entries)
            if name in files:
                raise PolicyViolation("ese archivo ya está registrado" if files[name] else "ese archivo fue RETIRADO: no se vuelve a registrar")
            if hd.data["sid"] in barred:
                raise PolicyViolation("ese archivo fue RETIRADO (con otra cabecera): no se vuelve a registrar")
            append("register", {"file": name})
        return name

    def withdraw(self, file: str, sid: str) -> None:
        """Retira UN archivo (huella de cabecera y `sid`) sin destruir la maestra: no habrá fichas nuevas para él (las ya emitidas siguen valiendo)."""
        _identifier(sid)
        with self.journal.transaction() as (entries, append):
            if not self._state(entries)[0].get(file):
                raise PolicyViolation("ese archivo no está registrado y activo")
            append("withdraw", {"file": file})
            append("bar", {"sid": sid})

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
        entry, file_key = self._file_key(hd)
        req = envelope.read_request(hd, request, int(self._clock()), envelope.lock_salt(hd, entry, file_key))
        name = hd.digest.hex()
        with self.journal.transaction() as (entries, append):
            files, requesters, delivered, barred = self._state(entries)
            if not files.get(name) or hd.data["sid"] in barred:
                raise PolicyViolation("archivo NO registrado por el guardián (o retirado)")
            if not requesters.get(req.requester):
                raise PolicyViolation("solicitante sin alta en el guardián (o dado de baja)")
            if not ct_equal(proof, prove(req.ident, self.requester_secret(req.requester))):
                raise AuthenticationFailure("prueba simétrica del solicitante inválida")
            if req.ident.hex() in delivered:
                raise PolicyViolation("esa solicitud YA se atendió: pide una nueva")
            _not_before_journal(req, entries)
            append("deliver", {"request": req.ident.hex(), "file": name, "requester": req.requester, "expires": req.expires, "reason": req.reason})
        return json.dumps({"v": 3, "file": name, "id": entry["id"], "key": envelope._b64(file_key)}, sort_keys=True).encode()

    def tick(self) -> None:
        """Latido: anota la hora. Programarlo periódicamente acorta lo que un reloj retrasado podría revivir."""
        with self.journal.transaction() as (_, append):
            append("tick", {})

    def deliveries(self) -> list[dict]:
        return [e["data"] for e in self.journal.read() if e["type"] == "deliver"]


class Custodian:
    """Un custodio CON MEMORIA: atiende cada solicitud una sola vez y deja constancia. `envelope.contribute` es la primitiva sin memoria."""

    def __init__(self, key, journal: str | Path, clock: Callable[[], float] = time.time, anchor: Anchors = None,
                 pinned_head: tuple[int, bytes] | None = None) -> None:
        self.key, self._clock = key, clock
        journal_key = hkdf(key.seed(), lp(b"QSEL3/custodian-journal"))
        self.journal = Journal(journal, journal_key, CUSTODIAN_EVENTS, clock, anchor, pinned_head)

    def contribute(self, path: str | Path, sender_public: bytes, request: bytes) -> bytes:
        now = int(self._clock())
        hd, _, _ = envelope.verify_file(path, sender_public)
        req = envelope.inspect_request(hd, request, now)  # la AUTORIZACIÓN la comprueba `contribute`, que es quien puede abrir la sal
        name, sid = hd.digest.hex(), hd.data["sid"]
        with self.journal.transaction() as (entries, append):
            if any(e["type"] == "withdraw" and e["data"]["sid"] == sid for e in entries):
                raise PolicyViolation("este custodio RETIRÓ ese archivo: no participa en abrirlo")
            if any(e["type"] == "serve" and e["data"]["request"] == req.ident.hex() for e in entries):
                raise PolicyViolation("esa solicitud YA se atendió: pide una nueva")
            _not_before_journal(req, entries)
            part = envelope.contribute(path, sender_public, self.key, request, now)  # si falla (no es custodio, archivo distinto) no se anota
            append("serve", {"request": req.ident.hex(), "file": name, "requester": req.requester, "expires": req.expires, "reason": req.reason})
        return part

    def withdraw(self, sid: str) -> None:
        """Deja de participar en abrir UN archivo (por su `sid`), para siempre. Revoca de hecho a un excustodio si quienes retiran dejan sin quórum a los demás."""
        _identifier(sid)
        with self.journal.transaction() as (entries, append):
            if any(e["type"] == "withdraw" and e["data"]["sid"] == sid for e in entries):
                raise PolicyViolation("ese archivo ya estaba retirado")
            append("withdraw", {"sid": sid})

    def tick(self) -> None:
        with self.journal.transaction() as (_, append):
            append("tick", {})

    def served(self) -> list[dict]:
        return [e["data"] for e in self.journal.read() if e["type"] == "serve"]
