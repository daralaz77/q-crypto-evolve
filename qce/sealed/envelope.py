"""Sobre poscuántico con QUÓRUM (laboratorio; sin revisión humana externa). Especificación byte a byte: docs/SEALED_ENVELOPE_SPEC.md.

El archivo se cifra con una clave que se reparte (Shamir) entre GRUPOS y cada grupo entre CUSTODIOS; cada participación viaja envuelta con el KEM híbrido de su
custodio (X-Wing en el nivel «standard», el híbrido propio con ML-KEM-1024 en «high»). El emisor FIRMA la cabecera y el archivo entero. Un custodio solo entrega ante
una SOLICITUD firmada, vigente y de un solicitante listado, y entrega su participación re-cifrada para la clave de apertura de esa solicitud. Opcionalmente el archivo
exige además CANDADOS simétricos (ver `keeper.py`), de modo que romper la criptografía de clave pública no baste para leerlo.

La envoltura de cada participación está ATADA a la política (cabecera v4 y v5): quien logre firmar como el emisor no puede trasplantar las participaciones de un
archivo a otra cabecera con otros solicitantes, candados o umbrales. Las cabeceras v3, sin esa atadura, solo se leen.

Modo DISCRETO (cabecera v5): la cabecera no identifica a custodios, solicitantes ni candados, no nombra los grupos y el cuerpo va acolchado (Padmé, mínimo 4 KiB).
Siguen visibles el emisor (su firma lo delata), el nivel, cuántos grupos, miembros, umbrales, solicitantes y candados hay, y el tamaño aproximado.

    MAGIC | u32 H | cabecera JSON (H bytes) | firma de cabecera | trozos AEAD (64 KiB + 16) | firma del archivo

Un RESGUARDO (`make_stub`) es la cabecera y las firmas sin el cuerpo: permite a custodios y guardián decidir sobre archivos grandes sin recibirlos.
"""
from __future__ import annotations

import base64
import contextlib
import hashlib
import itertools
import json
import os
import tempfile
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from ..core.encoding import lp
from ..core.errors import AuthenticationFailure, MalformedMessage, PolicyViolation
from ..pqc.hybrid import HIGH, LEVELS, HybridKemPrivateKey, HybridSigPrivateKey, hybrid_encapsulate, hybrid_verify
from ..pqc.xwing import CT_LEN as XWING_CT, PK_LEN as XWING_PK, XWingPrivateKey, xwing_encapsulate
from ..symmetric.aead import ct_equal, hkdf
from .shamir import combine, split

MAGIC = b"QSEL\x03\x00"
STUB_MAGIC = b"QSELSTUB"
MAX_SUBSETS = 256   # tope de subconjuntos probados cuando el emisor repartió mal
CHUNK = 65536
TAG = 16
MAX_HEADER = 1 << 20
MAX_GROUPS, MAX_MEMBERS = 8, 16
AEADS: dict[str, type[AESGCM] | type[ChaCha20Poly1305]] = {"AES-256-GCM": AESGCM, "CHACHA20-POLY1305": ChaCha20Poly1305}
CTX_HEADER, CTX_FILE, CTX_REQUEST = b"QSEL3/header", b"QSEL3/file", b"QSEL3/request"
MAX_OPENERS, MAX_REASON, MAX_LOCKS = 8, 500, 4
DEFAULT_TTL, MAX_TTL, CLOCK_SKEW = 86_400, 7 * 86_400, 300   # segundos: vida de una solicitud y desajuste de reloj tolerado
ZERO_NONCE = b"\x00" * 12  # SOLO con claves de un único uso (derivadas de un secreto KEM fresco)
V_LEGACY, V_OPEN, V_HIDDEN = 3, 4, 5   # versión de la cabecera: 3 solo se lee (envoltura sin atar); 5 = modo discreto
PAD_FLOOR = 4096           # en modo discreto ningún claro acolchado mide menos


# ---------------------------------------------------------------------------------------------------------------- suites de KEM
@dataclass(frozen=True)
class Suite:
    kem: str             # identificador que va en la cabecera firmada
    pk_len: int
    ct_len: int

    def generate(self):
        return XWingPrivateKey.generate() if self.kem == XWING.kem else HybridKemPrivateKey.generate(HIGH)

    def from_seed(self, seed: bytes):
        return XWingPrivateKey(seed) if self.kem == XWING.kem else HybridKemPrivateKey.from_seed(seed, HIGH)

    def encapsulate(self, public: bytes) -> tuple[bytes, bytes]:
        return xwing_encapsulate(public) if self.kem == XWING.kem else hybrid_encapsulate(public, HIGH)

    def owns(self, key: object) -> bool:
        """La clave PRIVADA es del tipo de esta suite. (Las claves públicas de X-Wing y del híbrido estándar de QCE miden lo mismo: no se distinguen por longitud.)"""
        if self.kem == XWING.kem:
            return isinstance(key, XWingPrivateKey)
        return isinstance(key, HybridKemPrivateKey) and key.level.name == "high"


XWING = Suite("X-Wing-draft11", XWING_PK, XWING_CT)
QCE_HIGH = Suite("QCE-X25519-MLKEM1024", HIGH.kem_pk_len, HIGH.kem_ct_len)
SUITES = {"standard": XWING, "high": QCE_HIGH}  # el NIVEL fija el KEM: no hay negociación ni degradación


# ---------------------------------------------------------------------------------------------------------------- utilidades
def _h(*parts: bytes) -> bytes:
    return hashlib.sha256(b"".join(lp(p) for p in parts)).digest()


def fingerprint(public_bytes: bytes) -> str:
    return hashlib.sha256(public_bytes).hexdigest()


def _int(n: int) -> bytes:
    return n.to_bytes(4, "big")


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _unb64(s: object, length: int) -> bytes:
    if not isinstance(s, str):
        raise MalformedMessage("se esperaba base64")
    try:
        b = base64.b64decode(s.encode("ascii"), validate=True)
    except (ValueError, UnicodeError) as exc:
        raise MalformedMessage("base64 inválido") from exc
    if len(b) != length or _b64(b) != s:  # codificación canónica
        raise MalformedMessage("longitud o codificación base64 inesperada")
    return b


def _hex32(s: object) -> bytes:
    if not isinstance(s, str) or len(s) != 64 or any(c not in "0123456789abcdef" for c in s):
        raise MalformedMessage("se esperaban 32 bytes en hexadecimal")
    return bytes.fromhex(s)


def _same_text(a: object, b: str) -> bool:
    return isinstance(a, str) and ct_equal(a.encode("utf-8", "surrogatepass"), b.encode())


def _no_dupes(pairs):
    d = dict(pairs)
    if len(d) != len(pairs):
        raise MalformedMessage("clave JSON repetida")
    return d


def _strict_json(raw: bytes) -> dict:
    try:
        obj = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_dupes)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise MalformedMessage("JSON inválido") from exc
    if not isinstance(obj, dict):
        raise MalformedMessage("se esperaba un objeto")
    return obj


def _keys(d: object, expected: set[str]) -> dict:
    if not isinstance(d, dict) or set(d) != expected:
        raise MalformedMessage(f"campos inesperados (se esperaban {sorted(expected)})")
    return d


def _count(v: object, lo: int, hi: int, what: str) -> int:
    if type(v) is not int or not lo <= v <= hi:
        raise MalformedMessage(f"{what} fuera de rango")
    return v


def _nonce(i: int, final: bool) -> bytes:
    return i.to_bytes(11, "big") + (b"\x01" if final else b"\x00")  # construcción STREAM: contador + marca de último trozo


# ---------------------------------------------------------------------------------------------------------------- modo discreto
def _blind_member(ss: bytes, sid: bytes) -> str:
    """Etiqueta de un custodio: solo quien puede desencapsular SU texto cifrado la reconoce."""
    return hkdf(ss, lp(b"QSEL3/blind-id") + lp(sid)).hex()


def _blind_opener(sid: bytes, salt: bytes, requester: str) -> str:
    return _h(b"QSEL3/blind-opener", sid, salt, bytes.fromhex(requester)).hex()


def _salt_commitment(sid: bytes, salt: bytes) -> str:
    """Todos los custodios y guardianes deben recibir LA MISMA sal: así la lista de solicitantes es la misma para todos."""
    return _h(b"QSEL3/blind-salt", sid, salt).hex()


def _salt_key(file_key: bytes, sid: bytes) -> bytes:
    return hkdf(file_key, lp(b"QSEL3/blind-salt-key") + lp(sid))


def lock_header_id(hidden: bool, sid: bytes, ident: bytes) -> str:
    """Cómo aparece un candado en la cabecera: su identificador o, en modo discreto, uno distinto en cada archivo."""
    return (_h(b"QSEL3/blind-lock", sid, ident)[:16] if hidden else ident).hex()


def padded_size(n: int) -> int:
    """Padmé: redondea hacia arriba dejando pocos bits significativos (como mucho un 12 % de más), con un mínimo."""
    if n <= PAD_FLOOR:
        return PAD_FLOOR
    e = n.bit_length() - 1
    mask = (1 << (e - e.bit_length())) - 1
    return (n + mask) & ~mask


class _Padded:
    """u64(longitud) ‖ claro ‖ ceros hasta `padded_size`, leído por trozos de `src`, que DEBE medir exactamente lo declarado."""

    def __init__(self, src, size: int) -> None:
        self._src, self._unread = src, size
        self._head = size.to_bytes(8, "big")
        self.size = self._left = padded_size(size + 8)

    def read(self, n: int) -> bytes:
        n = min(n, self._left)
        out = bytearray(self._head[:n])
        self._head = self._head[len(out):]
        while len(out) < n and self._unread:
            b = self._src.read(min(n - len(out), self._unread))
            if not b:
                raise MalformedMessage("el origen se acortó mientras se sellaba")
            out += b
            self._unread -= len(b)
        out += bytes(n - len(out))
        self._left -= n
        if not self._left and self._src.read(1):  # además, obliga a un origen en flujo a terminar sus comprobaciones
            raise MalformedMessage("el origen creció mientras se sellaba")
        return bytes(out)


def _unpadded(chunks: Iterator[bytes]) -> Iterator[bytes]:
    left: int | None = None
    for chunk in chunks:
        if left is None:
            if len(chunk) < 8:
                raise MalformedMessage("relleno imposible")
            left, chunk = int.from_bytes(chunk[:8], "big"), chunk[8:]
        data, pad = chunk[:left], chunk[left:]
        if pad.count(0) != len(pad):
            raise MalformedMessage("el relleno no es de ceros")
        left -= len(data)
        yield data
    if left:
        raise MalformedMessage("el relleno declara más datos de los que hay")


# ---------------------------------------------------------------------------------------------------------------- candado simétrico
@dataclass(frozen=True, repr=False)
class Lock:
    """Candado simétrico MAESTRO. `key` son 32 bytes ALEATORIOS (nunca derivados de una frase: el archivo publica un compromiso con el que se podrían probar
    candidatos). Lo guarda una persona o equipo distinto de los custodios, fuera de línea."""
    ident: bytes
    label: str
    key: bytes

    def __post_init__(self):
        if len(self.ident) != 16 or len(self.key) != 32 or not 1 <= len(self.label) <= 64 or not self.label.isprintable():
            raise PolicyViolation("candado inválido (identificador de 16 bytes, clave de 32 y etiqueta imprimible de 1 a 64)")

    def __repr__(self) -> str:  # nunca la clave en trazas ni registros
        return f"Lock({self.ident.hex()[:8]}…, {self.label!r})"

    @classmethod
    def generate(cls, label: str) -> "Lock":
        return cls(os.urandom(16), label, os.urandom(32))

    def file_key(self, sid: bytes) -> bytes:
        """Clave del candado PARA UN ARCHIVO: es lo único que sale del guardián; no permite derivar la maestra ni abrir otros archivos."""
        return hkdf(self.key, lp(b"QSEL3/lock-file") + lp(sid))


def _lock_commitment(sid: bytes, ident: bytes, file_key: bytes) -> str:
    return _h(b"QSEL3/lock", sid, ident, file_key).hex()


# ---------------------------------------------------------------------------------------------------------------- política y cabecera
@dataclass(frozen=True)
class Group:
    name: str
    k: int
    members: tuple[bytes, ...]  # claves públicas KEM híbridas de los custodios


@dataclass(frozen=True)
class Header:
    raw: bytes
    data: dict
    digest: bytes        # SHA-256 de MAGIC || longitud || cabecera
    payload_start: int
    stub: bool = False

    @property
    def level(self):
        return LEVELS[self.data["level"]]

    @property
    def suite(self) -> Suite:
        return SUITES[self.data["level"]]

    @property
    def hidden(self) -> bool:
        return self.data["v"] == V_HIDDEN

    def describe(self) -> dict:
        d = self.data
        return {"file_id": d["sid"], "discreet": self.hidden, "level": d["level"], "kem": d["kem"], "aead": d["aead"], "groups_needed": d["need"],
                "authorized_openers": d["openers"], "locks": [{"id": k["id"], "label": k["label"]} for k in d["locks"]],
                "groups": [{"name": g["name"], "k": g["k"], "members": [m["id"] for m in g["members"]]} for g in d["groups"]]}


def _box_len(hidden: bool) -> int:
    return (64 if hidden else 32) + TAG  # en modo discreto cada participación viaja con la sal de los solicitantes


def _check_header(obj: dict) -> dict:
    hidden = obj.get("v") == V_HIDDEN
    _keys(obj, {"v", "level", "kem", "aead", "sid", "sender", "need", "groups", "commit", "openers", "locks"} | ({"saltcom"} if hidden else set()))
    if type(obj["v"]) is not int or obj["v"] not in (V_LEGACY, V_OPEN, V_HIDDEN) or obj["level"] not in SUITES or obj["aead"] not in AEADS:
        raise MalformedMessage("versión, nivel o AEAD no admitidos")
    suite = SUITES[obj["level"]]
    if obj["kem"] != suite.kem:
        raise MalformedMessage("el KEM no es el que corresponde al nivel")
    _hex32(obj["sid"]), _hex32(obj["sender"]), _hex32(obj["commit"])
    if hidden:
        _hex32(obj["saltcom"])
    openers = obj["openers"]
    if not isinstance(openers, list) or not 1 <= len(openers) <= MAX_OPENERS:
        raise MalformedMessage("número de solicitantes autorizados fuera de rango")
    for o in openers:
        _hex32(o)
    locks = obj["locks"]
    if not isinstance(locks, list) or len(locks) > MAX_LOCKS:
        raise MalformedMessage("número de candados fuera de rango")
    lock_ids: set[str] = set()
    for k in locks:
        _keys(k, {"id", "label", "com"} | ({"salt"} if hidden else set()))
        if hidden:
            _unb64(k["salt"], 32 + TAG)
        if not isinstance(k["id"], str) or len(k["id"]) != 32 or any(c not in "0123456789abcdef" for c in k["id"]) or k["id"] in lock_ids:
            raise MalformedMessage("identificador de candado inválido o repetido")
        if not isinstance(k["label"], str) or not 1 <= len(k["label"]) <= 64 or not k["label"].isprintable():
            raise MalformedMessage("etiqueta de candado inválida")
        _hex32(k["com"])
        lock_ids.add(k["id"])
    groups = obj["groups"]
    if not isinstance(groups, list) or not 1 <= len(groups) <= MAX_GROUPS:
        raise MalformedMessage("número de grupos fuera de rango")
    _count(obj["need"], 1, len(groups), "grupos necesarios")
    seen: set[str] = set()
    for g in groups:
        _keys(g, {"name", "k", "com", "members"})
        if not isinstance(g["name"], str) or not 1 <= len(g["name"]) <= 64 or not g["name"].isprintable():
            raise MalformedMessage("nombre de grupo inválido")
        _hex32(g["com"])
        ms = g["members"]
        if not isinstance(ms, list) or not 1 <= len(ms) <= MAX_MEMBERS:
            raise MalformedMessage("número de custodios fuera de rango")
        _count(g["k"], 1, len(ms), "umbral del grupo")
        for m in ms:
            _keys(m, {"id", "ct", "box", "com"})
            _hex32(m["id"]), _hex32(m["com"])
            _unb64(m["ct"], suite.ct_len), _unb64(m["box"], _box_len(hidden))
            if m["id"] in seen:
                raise MalformedMessage("un custodio aparece dos veces: tendría dos participaciones")
            seen.add(m["id"])
    return obj


def _canonical_header(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _policy_digest(obj: dict) -> bytes:
    """Todo lo que la cabecera dice, salvo los textos cifrados de las participaciones (que dependen de esta huella)."""
    groups = [{**g, "members": [{"id": m["id"], "com": m["com"]} for m in g["members"]]} for g in obj["groups"]]
    return _h(b"QSEL3/policy", _canonical_header({**obj, "groups": groups}))


def _wrap_key(ss: bytes, sid: bytes, g: int, x: int, member_id: str, sender_id: str, policy: bytes | None) -> bytes:
    """`policy` None = formato 3."""
    label = (b"QSEL3/wrap",) if policy is None else (b"QSEL3/wrap-policy",)
    parts = label + (sid, _int(g), _int(x), bytes.fromhex(member_id), bytes.fromhex(sender_id)) + (() if policy is None else (policy,))
    return hkdf(ss, b"".join(lp(p) for p in parts))


def _payload_key(secret: bytes, header_digest: bytes, lock_keys: tuple[bytes, ...] = ()) -> bytes:
    """Secreto del quórum seguido de las claves por archivo de los candados, en el orden de la cabecera (todas de 32 bytes: sin ambigüedad)."""
    return hkdf(secret + b"".join(lock_keys), lp(b"QSEL3/payload") + lp(header_digest))


# ---------------------------------------------------------------------------------------------------------------- sellar
@contextlib.contextmanager
def _source(src):
    """(lector, tamaño) de una ruta o de un flujo que ya declara su tamaño."""
    if isinstance(src, (str, Path)):
        with open(src, "rb") as fh:
            yield fh, os.fstat(fh.fileno()).st_size
    else:
        yield src, src.size


def seal(src, dst: str | Path, sender: HybridSigPrivateKey, groups: list[Group], openers: list[bytes], need: int | None = None,
         aead: str = "AES-256-GCM", locks: list[Lock] | None = None, hidden: bool = False, _split=split) -> Header:
    """Sella `src` en `dst`. `openers` = claves públicas de FIRMA de quienes pueden pedir la apertura. `need` = cuántos grupos hacen falta (por defecto,
    todos). El nivel lo fija la clave del emisor. `hidden` = modo discreto."""
    level, suite = sender.level, SUITES[sender.level.name]
    need = len(groups) if need is None else need
    if aead not in AEADS or not 1 <= len(groups) <= MAX_GROUPS or not 1 <= need <= len(groups):
        raise PolicyViolation("política inválida")
    if not 1 <= len(openers) <= MAX_OPENERS or any(len(pk) != level.sig_pk_len for pk in openers):
        raise PolicyViolation("hace falta entre 1 y 8 solicitantes autorizados, con claves de firma del nivel del emisor")
    ids = [fingerprint(pk) for g in groups for pk in g.members]
    if len(set(ids)) != len(ids):
        raise PolicyViolation("un custodio no puede aparecer dos veces (tendría dos participaciones)")
    for g in groups:
        if not 1 <= len(g.members) <= MAX_MEMBERS or not 1 <= g.k <= len(g.members) or not 1 <= len(g.name) <= 64 or not g.name.isprintable():
            raise PolicyViolation(f"grupo inválido: {g.name!r}")
        if any(len(pk) != suite.pk_len for pk in g.members):
            raise PolicyViolation("todas las claves de custodio deben ser del nivel del emisor")
    locks = list(locks or [])
    if len(locks) > MAX_LOCKS or len({k.ident for k in locks}) != len(locks):
        raise PolicyViolation(f"entre 0 y {MAX_LOCKS} candados distintos")
    sid, secret, salt = os.urandom(32), os.urandom(32), os.urandom(32)
    lock_keys = tuple(k.file_key(sid) for k in locks)
    sender_id = fingerprint(sender.public_bytes)
    group_secrets = _split(secret, need, len(groups))
    out_groups, pending = [], []  # `pending`: (miembro, secreto KEM, participación); se envuelven cuando la cabecera está completa
    for gi, g in enumerate(groups, start=1):
        gs = group_secrets[gi]
        shares = _split(gs, g.k, len(g.members))
        members = []
        for x, pk in enumerate(g.members, start=1):
            share = shares[x]
            ss, ct = suite.encapsulate(pk)
            mid = _blind_member(ss, sid) if hidden else fingerprint(pk)
            com = _h(b"QSEL3/share", sid, _int(gi), _int(x), share)
            members.append({"id": mid, "ct": _b64(ct), "com": com.hex()})
            pending.append((gi, x, members[-1], ss, share))
        name = f"g{gi}" if hidden else g.name
        out_groups.append({"name": name, "k": g.k, "com": _h(b"QSEL3/group", sid, _int(gi), gs).hex(), "members": members})
    out_locks = []
    for k, fk in zip(locks, lock_keys, strict=True):
        ident = lock_header_id(hidden, sid, k.ident)
        entry = {"id": ident, "label": "candado" if hidden else k.label, "com": _lock_commitment(sid, bytes.fromhex(ident), fk)}
        if hidden:
            entry["salt"] = _b64(AESGCM(_salt_key(fk, sid)).encrypt(ZERO_NONCE, salt, bytes.fromhex(ident)))
        out_locks.append(entry)
    authorised = [fingerprint(pk) for pk in openers]
    obj = {"v": V_HIDDEN if hidden else V_OPEN, "level": level.name, "kem": suite.kem, "aead": aead, "sid": sid.hex(), "sender": sender_id, "need": need,
           "groups": out_groups, "commit": _h(b"QSEL3/key", sid, secret).hex(),
           "openers": [_blind_opener(sid, salt, who) for who in authorised] if hidden else authorised, "locks": out_locks}
    if hidden:
        obj["saltcom"] = _salt_commitment(sid, salt)
    policy = _policy_digest(obj)
    for gi, x, member, ss, share in pending:
        key = _wrap_key(ss, sid, gi, x, member["id"], sender_id, policy)
        member["box"] = _b64(AESGCM(key).encrypt(ZERO_NONCE, share + salt if hidden else share, bytes.fromhex(member["com"])))
    raw = _canonical_header(obj)
    if len(raw) > MAX_HEADER:
        raise PolicyViolation("cabecera demasiado grande")
    prefix = MAGIC + _int(len(raw)) + raw
    digest = hashlib.sha256(prefix).digest()
    head_sig = sender.sign(prefix, CTX_HEADER)
    cipher = AEADS[aead](_payload_key(secret, digest, lock_keys))
    dst = Path(dst)
    payload_hash, length = hashlib.sha256(), 0
    with _source(src) as (plain, size), _atomic_output(dst) as fout:
        fin = _Padded(plain, size) if hidden else plain
        fout.write(prefix + head_sig)
        i, chunk = 0, fin.read(CHUNK)
        while True:
            nxt = fin.read(CHUNK) if len(chunk) == CHUNK else b""
            final = not nxt
            c = cipher.encrypt(_nonce(i, final), chunk, None)
            fout.write(c)
            payload_hash.update(c)
            length += len(c)
            if final:
                break
            i, chunk = i + 1, nxt
        fout.write(sender.sign(digest + payload_hash.digest() + length.to_bytes(8, "big"), CTX_FILE))
    return Header(raw, obj, digest, len(prefix) + len(head_sig))


class _atomic_output:
    """Escribe en un temporal 0600 del mismo directorio y solo lo renombra si TODO salió bien: nunca queda un destino a medias o sin verificar."""

    def __init__(self, dst: Path) -> None:
        self.dst = dst

    def __enter__(self):
        fd, self.tmp = tempfile.mkstemp(dir=self.dst.parent, prefix=f".{self.dst.name}-")
        self.fh = os.fdopen(fd, "wb")
        return self.fh

    def __exit__(self, exc_type, exc, tb):
        try:
            if exc_type is None:
                self.fh.flush()
                os.fsync(self.fh.fileno())
            self.fh.close()
            if exc_type is None:
                os.replace(self.tmp, self.dst)
        finally:
            if os.path.exists(self.tmp):
                os.unlink(self.tmp)
        return False


# ---------------------------------------------------------------------------------------------------------------- leer y verificar
def read_header(path: str | Path, sender_public: bytes) -> Header:
    """Verifica la firma de cabecera con la clave del emisor que EL LECTOR ya conoce (nunca una que venga dentro del archivo)."""
    with open(path, "rb") as fh:
        stub = fh.read(len(STUB_MAGIC)) == STUB_MAGIC
        base = len(STUB_MAGIC) if stub else 0
        fh.seek(base)
        start = fh.read(len(MAGIC) + 4)
        if len(start) != len(MAGIC) + 4 or start[: len(MAGIC)] != MAGIC:
            raise MalformedMessage("no es un archivo Q-Sello")
        n = int.from_bytes(start[len(MAGIC):], "big")
        if not 2 <= n <= MAX_HEADER:
            raise MalformedMessage("longitud de cabecera fuera de rango")
        raw = fh.read(n)
        if len(raw) != n:
            raise MalformedMessage("cabecera truncada")
        level = next((lv for lv in LEVELS.values() if len(sender_public) == lv.sig_pk_len), None)
        if level is None:
            raise AuthenticationFailure("clave de emisor de longitud inválida")
        sig = fh.read(level.sig_len)
        prefix = start + raw
        hybrid_verify(sender_public, prefix, sig, CTX_HEADER, level)  # ANTES de interpretar el JSON
        obj = _check_header(_strict_json(raw))
        if obj["level"] != level.name or not _same_text(obj["sender"], fingerprint(sender_public)):
            raise AuthenticationFailure("la cabecera no corresponde a este emisor")
        return Header(raw, obj, hashlib.sha256(prefix).digest(), base + len(prefix) + len(sig), stub)


def verify_file(path: str | Path, sender_public: bytes) -> tuple[Header, bytes, int]:
    """Primera pasada: firma de cabecera Y firma del archivo entero. Devuelve (cabecera, hash del cuerpo cifrado, longitud del cuerpo)."""
    hd = read_header(path, sender_public)
    level = hd.level
    size = os.path.getsize(path)
    if hd.stub:
        with open(path, "rb") as fh:
            fh.seek(hd.payload_start)
            tail = fh.read(40 + level.sig_len + 1)
        if len(tail) != 40 + level.sig_len:
            raise MalformedMessage("resguardo truncado o con bytes de más")
        body_hash, length, sig = tail[:32], int.from_bytes(tail[32:40], "big"), tail[40:]
        if length < TAG:
            raise MalformedMessage("resguardo con un cuerpo imposible")
        hybrid_verify(sender_public, hd.digest + body_hash + tail[32:40], sig, CTX_FILE, level)
        return hd, body_hash, length
    length = size - hd.payload_start - level.sig_len
    if length < TAG:
        raise MalformedMessage("archivo truncado")
    ph = hashlib.sha256()
    with open(path, "rb") as fh:
        fh.seek(hd.payload_start)
        left = length
        while left:
            b = fh.read(min(left, 1 << 20))
            if not b:
                raise MalformedMessage("archivo truncado")
            ph.update(b)
            left -= len(b)
        sig = fh.read(level.sig_len)
    hybrid_verify(sender_public, hd.digest + ph.digest() + length.to_bytes(8, "big"), sig, CTX_FILE, level)
    return hd, ph.digest(), length


def make_stub(path: str | Path, sender_public: bytes) -> bytes:
    """Resguardo de un archivo ÍNTEGRO: cabecera firmada, huella y longitud del cuerpo y la firma del archivo. Quien lo recibe verifica la MISMA firma del emisor;
    no puede comprobar el cuerpo (no lo tiene), pero la firma ata su huella y quien abre la exige."""
    hd, body_hash, length = verify_file(path, sender_public)
    if hd.stub:
        raise PolicyViolation("ya es un resguardo")
    with open(path, "rb") as fh:
        head = fh.read(hd.payload_start)
        fh.seek(-hd.level.sig_len, os.SEEK_END)
        sig = fh.read(hd.level.sig_len)
    return STUB_MAGIC + head + body_hash + length.to_bytes(8, "big") + sig


# ---------------------------------------------------------------------------------------------------------------- custodio y apertura
def _slot(hd: Header, custodian) -> tuple[int, int, dict, bytes]:
    """(grupo, posición, miembro, secreto KEM) de este custodio. En modo discreto prueba cada hueco: solo en el suyo la etiqueta coincide."""
    suite, sid = hd.suite, bytes.fromhex(hd.data["sid"])
    own = None if hd.hidden else fingerprint(custodian.public_bytes)
    for gi, g in enumerate(hd.data["groups"], start=1):
        for x, m in enumerate(g["members"], start=1):
            if own is not None and m["id"] != own:
                continue
            try:
                ss = custodian.decapsulate(_unb64(m["ct"], suite.ct_len))
            except (ValueError, AuthenticationFailure) as exc:  # basura de un emisor defectuoso
                if own is not None:
                    raise AuthenticationFailure("el texto cifrado de esta participación es inválido") from exc
                continue  # en modo discreto puede ser el hueco de otro: se sigue buscando
            if own is not None or ct_equal(bytes.fromhex(m["id"]), bytes.fromhex(_blind_member(ss, sid))):
                return gi, x, m, ss
    raise PolicyViolation("esta clave no es de ningún custodio del archivo")


def _unwrap(hd: Header, custodian) -> tuple[int, int, bytes, bytes]:
    """(grupo, posición, participación, sal) de este custodio, comprobada contra su compromiso."""
    if not hd.suite.owns(custodian):
        raise PolicyViolation("la clave del custodio es de otro nivel o de otro KEM")
    gi, x, m, ss = _slot(hd, custodian)
    sid, com = bytes.fromhex(hd.data["sid"]), bytes.fromhex(m["com"])
    wk = _wrap_key(ss, sid, gi, x, m["id"], hd.data["sender"], None if hd.data["v"] == V_LEGACY else _policy_digest(hd.data))
    try:
        plain = AESGCM(wk).decrypt(ZERO_NONCE, _unb64(m["box"], _box_len(hd.hidden)), com)
    except InvalidTag as exc:
        raise AuthenticationFailure("la participación envuelta no se puede abrir: otra clave, o no pertenece a esta política") from exc
    share, salt = plain[:32], plain[32:]
    if not ct_equal(com, _h(b"QSEL3/share", sid, _int(gi), _int(x), share)):
        raise AuthenticationFailure("la participación no cumple su compromiso (emisor defectuoso)")
    return gi, x, share, salt


def lock_salt(hd: Header, entry: dict, file_key: bytes) -> bytes:
    """La sal de los solicitantes que un candado lleva para su guardián (vacía fuera del modo discreto)."""
    if not hd.hidden:
        return b""
    sid = bytes.fromhex(hd.data["sid"])
    try:
        return AESGCM(_salt_key(file_key, sid)).decrypt(ZERO_NONCE, _unb64(entry["salt"], 32 + TAG), bytes.fromhex(entry["id"]))
    except InvalidTag as exc:
        raise AuthenticationFailure("la sal del candado no se puede abrir") from exc


def _contrib_context(hd: Header, gi: int, x: int, opener_public: bytes) -> bytes:
    return b"".join(lp(p) for p in (b"QSEL3/contrib", hd.digest, _int(gi), _int(x), hashlib.sha256(opener_public).digest()))


def _request_message(header_digest: bytes, kem_public: bytes, signer_public: bytes, reason: str, issued: int, expires: int, nonce: bytes) -> bytes:
    return b"".join(lp(p) for p in (header_digest, kem_public, signer_public, reason.encode("utf-8"), issued.to_bytes(8, "big"), expires.to_bytes(8, "big"), nonce))


@dataclass(frozen=True)
class Request:
    opening_key: bytes
    reason: str
    requester: str       # huella
    issued: int
    expires: int
    ident: bytes         # SHA-256 del MENSAJE firmado (no de los bytes JSON: reescribir el JSON no crea «otra» solicitud)


def request_open(path: str | Path, sender_public: bytes, requester: HybridSigPrivateKey, opening_key_public: bytes, reason: str, ttl: int = DEFAULT_TTL,
                 now: int | None = None) -> bytes:
    """Quien quiere abrir firma: ESTE archivo, ESTA clave efímera de apertura, el MOTIVO y hasta CUÁNDO vale. Es lo que cada custodio y el guardián revisan."""
    hd, _, _ = verify_file(path, sender_public)
    # En modo discreto el propio solicitante no puede saber si está en la lista: lo comprueban custodios y guardián.
    if requester.level.name != hd.data["level"] or (not hd.hidden and fingerprint(requester.public_bytes) not in hd.data["openers"]):
        raise PolicyViolation("este solicitante no está autorizado para este archivo")
    if not 1 <= len(reason) <= MAX_REASON or not reason.isprintable() or len(opening_key_public) != hd.suite.pk_len:
        raise PolicyViolation("motivo o clave de apertura inválidos")
    if not 1 <= ttl <= MAX_TTL:
        raise PolicyViolation(f"la solicitud debe durar entre 1 y {MAX_TTL} segundos")
    issued = int(time.time()) if now is None else now
    nonce = os.urandom(16)
    sig = requester.sign(_request_message(hd.digest, opening_key_public, requester.public_bytes, reason, issued, issued + ttl, nonce), CTX_REQUEST)
    return json.dumps({"v": 4, "file": hd.digest.hex(), "kem": _b64(opening_key_public), "signer": _b64(requester.public_bytes), "reason": reason,
                       "issued": issued, "expires": issued + ttl, "nonce": _b64(nonce), "sig": _b64(sig)}, sort_keys=True, ensure_ascii=False).encode("utf-8")


def read_request(hd: Header, blob: bytes, now: int | None = None, salt: bytes = b"") -> Request:
    """Verifica una solicitud contra la cabecera FIRMADA y contra el reloj de quien la lee, y que su firmante esté AUTORIZADO (en modo discreto hace falta la sal)."""
    req = inspect_request(hd, blob, now)
    sid = bytes.fromhex(hd.data["sid"])
    if hd.hidden and not ct_equal(bytes.fromhex(hd.data["saltcom"]), bytes.fromhex(_salt_commitment(sid, salt))):
        raise AuthenticationFailure("la sal de los solicitantes falta o no es la comprometida en la cabecera")
    if (_blind_opener(sid, salt, req.requester) if hd.hidden else req.requester) not in hd.data["openers"]:
        raise PolicyViolation("solicitante NO autorizado por la cabecera")
    return req


def inspect_request(hd: Header, blob: bytes, now: int | None = None) -> Request:
    """Firma y vigencia de una solicitud, SIN comprobar que su firmante esté autorizado. Solo sirve para mostrarla: quien entrega algo usa `read_request`."""
    r = _keys(_strict_json(blob), {"v", "file", "kem", "signer", "reason", "issued", "expires", "nonce", "sig"})
    level = hd.level
    if type(r["v"]) is not int or r["v"] != 4 or not _same_text(r["file"], hd.digest.hex()):
        raise PolicyViolation("la solicitud es de OTRO archivo o de otra versión")
    signer, kem, nonce = _unb64(r["signer"], level.sig_pk_len), _unb64(r["kem"], hd.suite.pk_len), _unb64(r["nonce"], 16)
    reason = r["reason"]
    if not isinstance(reason, str) or not 1 <= len(reason) <= MAX_REASON or not reason.isprintable():
        raise MalformedMessage("motivo inválido")
    issued = _count(r["issued"], 0, 2**62, "fecha de emisión")
    expires = _count(r["expires"], issued + 1, issued + MAX_TTL, "caducidad")
    message = _request_message(hd.digest, kem, signer, reason, issued, expires, nonce)
    hybrid_verify(signer, message, _unb64(r["sig"], level.sig_len), CTX_REQUEST, level)
    now = int(time.time()) if now is None else now
    if now > expires:
        raise PolicyViolation("la solicitud ha CADUCADO")
    if now < issued - CLOCK_SKEW:
        raise PolicyViolation("la solicitud viene del FUTURO (revisar los relojes)")
    return Request(kem, reason, fingerprint(signer), issued, expires, hashlib.sha256(message).digest())


def contribute(path: str | Path, sender_public: bytes, custodian, request: bytes, now: int | None = None) -> bytes:
    """El custodio verifica TODO el archivo y la SOLICITUD firmada, y entrega su participación re-cifrada para la clave de apertura de esa solicitud."""
    hd, _, _ = verify_file(path, sender_public)
    gi, x, share, salt = _unwrap(hd, custodian)
    opener_public = read_request(hd, request, now, salt).opening_key
    suite = hd.suite
    ss2, ct2 = suite.encapsulate(opener_public)
    ctx = _contrib_context(hd, gi, x, opener_public)
    box = AESGCM(hkdf(ss2, ctx)).encrypt(ZERO_NONCE, share, ctx)
    return json.dumps({"v": 3, "file": hd.digest.hex(), "g": gi, "x": x, "ct": _b64(ct2), "box": _b64(box)}, sort_keys=True).encode()


def _lock_keys(hd: Header, tokens: list[bytes]) -> tuple[bytes, ...]:
    """Una clave por cada candado de la cabecera, en su orden. Falta una, o es de otro archivo, o no cumple el compromiso: se niega."""
    sid = bytes.fromhex(hd.data["sid"])
    got: dict[str, bytes] = {}
    for blob in tokens:
        t = _keys(_strict_json(blob), {"v", "file", "id", "key"})
        if type(t["v"]) is not int or t["v"] != 3 or not _same_text(t["file"], hd.digest.hex()):
            raise PolicyViolation("la ficha de candado es de OTRO archivo")
        entry = next((k for k in hd.data["locks"] if k["id"] == t["id"]), None)
        if entry is None:
            raise PolicyViolation("ficha de un candado que este archivo no tiene")
        key = _unb64(t["key"], 32)
        if not ct_equal(bytes.fromhex(entry["com"]), bytes.fromhex(_lock_commitment(sid, bytes.fromhex(entry["id"]), key))):
            raise AuthenticationFailure("la ficha de candado no cumple el compromiso firmado")
        got[entry["id"]] = key
    missing = [k["label"] for k in hd.data["locks"] if k["id"] not in got]
    if missing:
        raise PolicyViolation(f"falta la ficha del candado: {', '.join(missing)}")
    return tuple(got[k["id"]] for k in hd.data["locks"])


def _check_contribution(hd: Header, blob: bytes, opener) -> tuple[int, int, bytes]:
    c = _keys(_strict_json(blob), {"v", "file", "g", "x", "ct", "box"})
    if type(c["v"]) is not int or c["v"] != 3 or not _same_text(c["file"], hd.digest.hex()):
        raise PolicyViolation("es de OTRO archivo")
    gi = _count(c["g"], 1, len(hd.data["groups"]), "grupo")
    members = hd.data["groups"][gi - 1]["members"]
    x = _count(c["x"], 1, len(members), "posición")
    ss = opener.decapsulate(_unb64(c["ct"], hd.suite.ct_len))
    ctx = _contrib_context(hd, gi, x, opener.public_bytes)
    try:
        share = AESGCM(hkdf(ss, ctx)).decrypt(ZERO_NONCE, _unb64(c["box"], 32 + TAG), ctx)
    except InvalidTag as exc:
        raise AuthenticationFailure("no es para esta apertura o fue alterada") from exc
    if not ct_equal(bytes.fromhex(members[x - 1]["com"]), _h(b"QSEL3/share", bytes.fromhex(hd.data["sid"]), _int(gi), _int(x), share)):
        raise AuthenticationFailure("participación INCORRECTA: no coincide con el compromiso firmado")
    return gi, x, share


def _matching_subset(points: dict[int, bytes], k: int, matches) -> bytes | None:
    """Busca k participaciones cuyo secreto cumpla el compromiso: primero las k primeras y luego dejando fuera 1, 2, … (así una o dos defectuosas no bloquean un
    quórum sobrado). Cualquier resultado aceptado cumple el MISMO compromiso: nunca hay dos secretos distintos."""
    slots = sorted(points)
    tried: set[tuple[int, ...]] = set()
    for left_out in range(len(slots) - k + 1):
        for out in itertools.combinations(slots, left_out):
            chosen = tuple(x for x in slots if x not in out)[:k]
            if chosen in tried:
                continue
            tried.add(chosen)
            candidate = combine({x: points[x] for x in chosen})
            if matches(candidate):
                return candidate
            if len(tried) >= MAX_SUBSETS:
                return None
    return None


def recover_secret(hd: Header, shares: dict[tuple[int, int], bytes]) -> bytes:
    """Reconstruye K a partir de participaciones YA comprobadas. Cualquier quórum obtiene exactamente la clave comprometida, o falla."""
    sid = bytes.fromhex(hd.data["sid"])
    group_secrets: dict[int, bytes] = {}
    missing, broken = [], []
    for gi, g in enumerate(hd.data["groups"], start=1):
        mine = {x: s for (gg, x), s in sorted(shares.items()) if gg == gi}
        if len(mine) < g["k"]:
            missing.append(f"{g['name']}: {len(mine)}/{g['k']}")
            continue
        expected = bytes.fromhex(g["com"])
        gs = _matching_subset(mine, g["k"], lambda c, e=expected, i=gi: ct_equal(e, _h(b"QSEL3/group", sid, _int(i), c)))
        if gs is None:
            broken.append(g["name"])
            continue
        group_secrets[gi] = gs
    need = hd.data["need"]
    if len(group_secrets) < need:
        if broken:
            raise AuthenticationFailure(f"reparto INCONSISTENTE en el grupo {', '.join(map(repr, broken))}: el emisor no repartió un mismo secreto")
        raise PolicyViolation(f"quórum insuficiente: {len(group_secrets)}/{need} grupos completos ({'; '.join(missing)})")
    commitment = bytes.fromhex(hd.data["commit"])
    secret = _matching_subset(group_secrets, need, lambda c: ct_equal(commitment, _h(b"QSEL3/key", sid, c)))
    if secret is None:
        raise AuthenticationFailure("reparto INCONSISTENTE entre grupos: la clave no coincide con su compromiso")
    return secret


def _unlock(path: str | Path, sender_public: bytes, opener, contributions: list[bytes], lock_tokens: list[bytes] | None):
    """Verifica el archivo y reconstruye la clave del cuerpo: (cabecera, huella del cuerpo, longitud, cifrador, informe)."""
    hd, body_hash, length = verify_file(path, sender_public)
    if hd.stub:
        raise PolicyViolation("es un resguardo: para abrir hace falta el archivo completo")
    if not hd.suite.owns(opener):
        raise PolicyViolation("la clave de apertura es de otro nivel o de otro KEM")
    lock_keys = _lock_keys(hd, list(lock_tokens or []))
    shares: dict[tuple[int, int], bytes] = {}
    rejected = []
    for n, blob in enumerate(contributions):
        try:
            gi, x, share = _check_contribution(hd, blob, opener)
        except (AuthenticationFailure, MalformedMessage, PolicyViolation) as exc:
            rejected.append({"index": n, "reason": str(exc)})
            continue
        shares[(gi, x)] = share
    try:
        secret = recover_secret(hd, shares)
    except PolicyViolation as exc:
        detail = "; ".join(f"contribución {r['index']}: {r['reason']}" for r in rejected)
        raise PolicyViolation(f"{exc}" + (f" | rechazadas -> {detail}" if detail else "")) from exc
    cipher = AEADS[hd.data["aead"]](_payload_key(secret, hd.digest, lock_keys))
    return hd, body_hash, length, cipher, {"used": sorted(shares), "rejected": rejected}


def _body_chunks(path: str | Path, hd: Header, body_hash: bytes, length: int, cipher) -> Iterator[bytes]:
    """Descifra trozo a trozo. El ÚLTIMO no se entrega sin comprobar que el cuerpo leído es el que se verificó: quien consume no necesita pedir nada más."""
    ph = hashlib.sha256()
    with open(path, "rb") as fin:
        fin.seek(hd.payload_start)
        left, i = length, 0
        while left:
            c = fin.read(min(left, CHUNK + TAG))
            if not c:
                raise MalformedMessage("archivo truncado")
            left -= len(c)
            ph.update(c)
            try:
                plain = cipher.decrypt(_nonce(i, left == 0), c, None)
            except InvalidTag as exc:
                raise AuthenticationFailure(f"trozo {i} alterado, desordenado o truncado") from exc
            if not left and not ct_equal(ph.digest(), body_hash):  # el archivo cambió entre la verificación y el descifrado: no se publica la salida
                raise AuthenticationFailure("el archivo cambió mientras se abría")
            yield plain
            i += 1


def _plaintext(path: str | Path, hd: Header, body_hash: bytes, length: int, cipher) -> tuple[int, Iterator[bytes]]:
    """(tamaño del claro, sus trozos), sin el relleno del modo discreto."""
    chunks = _body_chunks(path, hd, body_hash, length, cipher)
    if not hd.hidden:
        return length - TAG * -(-length // (CHUNK + TAG)), chunks
    first = next(chunks)
    return int.from_bytes(first[:8], "big"), _unpadded(itertools.chain([first], chunks))


class _Stream:
    """Un claro en memoria, trozo a trozo, con la forma que espera `seal`: nunca toca el disco."""

    def __init__(self, size: int, chunks: Iterator[bytes]) -> None:
        self.size, self._chunks, self._buffer = size, chunks, bytearray()

    def read(self, n: int) -> bytes:
        while len(self._buffer) < n:
            more = next(self._chunks, None)
            if more is None:
                break
            self._buffer += more
        out = bytes(self._buffer[:n])
        del self._buffer[:n]
        return out


def open_sealed(path: str | Path, dst: str | Path, sender_public: bytes, opener, contributions: list[bytes], lock_tokens: list[bytes] | None = None) -> dict:
    """Abre el archivo. Las contribuciones defectuosas se informan y se descartan; si quedan suficientes, se abre igual."""
    hd, body_hash, length, cipher, report = _unlock(path, sender_public, opener, contributions, lock_tokens)
    _, chunks = _plaintext(path, hd, body_hash, length, cipher)
    with _atomic_output(Path(dst)) as fout:
        for chunk in chunks:
            fout.write(chunk)
    return report


def reseal(path: str | Path, dst: str | Path, sender_public: bytes, opener, contributions: list[bytes], new_sender: HybridSigPrivateKey, groups: list[Group],
           openers: list[bytes], need: int | None = None, locks: list[Lock] | None = None, lock_tokens: list[bytes] | None = None,
           aead: str | None = None, hidden: bool | None = None, drop_locks: bool = False) -> tuple[Header, dict]:
    """ROTACIÓN: abre con el quórum actual y vuelve a sellar con otra política (clave nueva) sin escribir el claro en disco. Por sí solo NO invalida las copias
    antiguas: eso lo hacen el guardián (retirar o destruir el candado viejo) y los custodios que retiren el archivo anterior. Quien lo ejecuta ve el claro.
    El cifrado y el modo discreto se heredan; dejar el archivo con MENOS candados exige pedirlo (`drop_locks`)."""
    if Path(dst).exists() and os.path.samefile(path, dst):
        raise PolicyViolation("no se vuelve a sellar sobre el archivo original")
    hd, body_hash, length, cipher, report = _unlock(path, sender_public, opener, contributions, lock_tokens)
    if len(locks or []) < len(hd.data["locks"]) and not drop_locks:
        raise PolicyViolation("la política nueva lleva MENOS candados que el archivo: indícalos todos o pide expresamente quitarlos")
    stream = _Stream(*_plaintext(path, hd, body_hash, length, cipher))
    header = seal(stream, dst, new_sender, groups, openers, need, aead or hd.data["aead"], locks, hd.hidden if hidden is None else hidden)
    return header, report
