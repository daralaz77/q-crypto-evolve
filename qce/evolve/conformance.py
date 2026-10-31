"""Conformidad modelo-código de QCE1 (paso 6): trazas del CÓDIGO REAL contra el modelo formal (formal/qce1.spthy).

Qué hace
  1. Ejecuta el código real (ClientHandshake/ServerHandshake) con un atacante activo que controla la red.
  2. Convierte cada ejecución en EVENTOS con los mismos nombres y argumentos que las acciones del modelo
     (ClientStart, ServerStart, ClientFinishSent, ServerDone, ClientDone, RevealLTK), calculados con código
     INDEPENDIENTE escrito solo a partir de la especificación (docs/QCE1_SPEC.md), nunca con funciones de qce.
  3. Comprueba sobre esas trazas las fórmulas de los lemas del modelo (acuerdo inyectivo, anti-degradación,
     la firma liga los Hello).
  4. Comprueba las DECISIONES: en cada paso con guarda (los `Eq(...)` de las reglas del modelo) el código solo
     puede aceptar si la guarda independiente se cumple. El código puede ser MÁS estricto que el modelo
     (política de suites, longitudes, un único intento), nunca más permisivo.
  5. Reproduce en el código real las falsificaciones esperadas del modelo (LTK revelada, ≈ Ed25519+ML-DSA rotos;
     clave KEM efímera filtrada, ≈ X25519+ML-KEM rotos) para comprobar que el código no es ni más ni menos débil.

Qué NO hace: no demuestra el código ni las primitivas; solo que las trazas observadas son trazas del modelo.
"""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field
from unittest import mock

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ..core.errors import QCEError
from ..core.policy import Policy
from ..pqc.hybrid import HybridKemPrivateKey, HybridSigPrivateKey
from ..protocols import session as S

CTX = b"QCE1/server-hello"
LABEL_KEM = b"QCE1/hybrid-kem/X25519+ML-KEM-768"
SERVER = "S"  # nombre simbólico del servidor fijado, como $S en el modelo


# ---- implementación independiente (solo spec) ---------------------------------------------------------------------------
def H(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for p in parts:
        h.update(len(p).to_bytes(4, "big") + p)
    return h.digest()


def parse(msg: bytes, kind: int, n: int) -> list[bytes] | None:
    try:
        if len(msg) < 2 or msg[0] != kind or msg[1] != n:
            return None
        pos, out = 2, []
        for _ in range(n):
            ln = int.from_bytes(msg[pos:pos + 4], "big")
            pos += 4
            if len(msg[pos:pos + ln]) != ln or ln > 16384:
                return None
            out.append(msg[pos:pos + ln])
            pos += ln
        return out if pos == len(msg) else None
    except Exception:
        return None


def pack(kind: int, fields: list[bytes]) -> bytes:
    return bytes([kind, len(fields)]) + b"".join(len(f).to_bytes(4, "big") + f for f in fields)


def keys_from(secret: bytes, th: bytes) -> dict[str, bytes]:
    okm = HKDF(algorithm=hashes.SHA256(), length=104, salt=th, info=b"QCE1/keys" + th).derive(secret)
    return {"c2s": okm[0:32], "s2c": okm[32:64], "ck": okm[64:96]}


def mac(k: bytes, m: bytes) -> bytes:
    return hmac.new(k, m, hashlib.sha256).digest()


def verify_server_hello(pinned: bytes, m1: bytes, fields: list[bytes] | None) -> bool:
    """Guarda de la regla C2 del modelo: ambas firmas válidas sobre H(m1, suite, nonce_s, kpk, fp(identidad))."""
    if fields is None:
        return False
    suite, nonce_s, kpk, sig = fields
    signed = H(m1, suite, nonce_s, kpk, hashlib.sha256(pinned).digest())
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(pinned[:32]).verify(sig[:64], CTX + b"\x00" + signed)
        mldsa.MLDSA65PublicKey.from_public_bytes(pinned[32:]).verify(sig[64:], signed, CTX)
        return True
    except (InvalidSignature, ValueError):
        return False


# ---- trazas ----------------------------------------------------------------------------------------------------------------
@dataclass
class Decision:
    step: str  # C2 | S2 | C3
    accepted: bool
    guard: bool | None  # guarda del modelo evaluada de forma independiente (None = el paso no llegó a calcularse)
    error: str = ""


@dataclass
class Trace:
    events: list[tuple] = field(default_factory=list)
    decisions: list[Decision] = field(default_factory=list)
    scenario: str = ""
    sessions: tuple | None = None  # (cliente, servidor) si ambos terminaron
    adversary_keys: set = field(default_factory=set)  # claves de sesión que el atacante pudo calcular


def _offered(m1: bytes) -> bytes:
    f = parse(m1, 1, 4)
    return f[2] if f else b""


def _suite(m2: bytes) -> bytes:
    f = parse(m2, 2, 4)
    return f[0] if f else b""


class _Spies:
    """Captura los secretos que el código calcula (solo para que el ORÁCULO independiente derive las mismas claves)."""

    def __init__(self) -> None:
        self.k_client: bytes | None = None
        self.k_server: bytes | None = None
        self.leaked_ephemeral: list[HybridKemPrivateKey] = []

    def __enter__(self):
        real_enc, real_dec, real_gen = S.hybrid_encapsulate, HybridKemPrivateKey.decapsulate, HybridKemPrivateKey.generate.__func__

        def enc(pk, *a, **kw):
            k, ct = real_enc(pk, *a, **kw)
            self.k_client = k
            return k, ct

        def dec(slf, ct):
            k = real_dec(slf, ct)
            self.k_server = k
            return k

        def gen(cls, *a, **kw):
            k = real_gen(cls, *a, **kw)
            self.leaked_ephemeral.append(k)
            return k
        self._p = [mock.patch.object(S, "hybrid_encapsulate", enc), mock.patch.object(HybridKemPrivateKey, "decapsulate", dec),
                   mock.patch.object(HybridKemPrivateKey, "generate", classmethod(gen))]
        for p in self._p:
            p.start()
        return self

    def __exit__(self, *a):
        for p in self._p:
            p.stop()


Plan = dict  # posición (1..4) -> ("pass",) | ("drop",) | ("flip", pos) | ("replace", bytes)


def _apply(plan: Plan, pos: int, msg: bytes) -> bytes | None:
    act = plan.get(pos, ("pass",))
    if act[0] == "drop":
        return None
    if act[0] == "flip":
        b = bytearray(msg)
        b[act[1] % len(b)] ^= 0x5A
        return bytes(b)
    if act[0] == "replace":
        return act[1]
    return msg


def run_session(ident: HybridSigPrivateKey, policy: Policy, plan: Plan, qkd: tuple[bytes, bytes] | None = None,
                server_ident: HybridSigPrivateKey | None = None, scenario: str = "aleatorio") -> tuple[Trace, list[bytes]]:
    """Una ejecución con un atacante de red. Devuelve la traza y los 4 mensajes originales (para repetirlos en otras sesiones)."""
    tr, wire = Trace(scenario=scenario), []
    qk = qkd[1] if qkd else b""
    with _Spies() as sp:
        c = S.ClientHandshake(ident.public_bytes, policy, qkd=qkd)
        srv = S.ServerHandshake(server_ident or ident, policy, qkd_lookup=lambda i: qk if qkd and i == qkd[0] else None)
        m1 = c.start()
        wire.append(m1)
        tr.events.append(("ClientStart", SERVER, parse(m1, 1, 4)[1]))
        m1w = _apply(plan, 1, m1)
        if m1w is None:
            return tr, wire
        try:
            m2 = srv.on_client_hello(m1w)
        except QCEError:
            return tr, wire
        wire.append(m2)
        tr.events.append(("ServerStart", SERVER, m1w, m2))
        m2w = _apply(plan, 2, m2)
        if m2w is None:
            return tr, wire

        # ---- C2: el cliente recibe ServerHello
        guard = verify_server_hello(ident.public_bytes, m1, parse(m2w, 2, 4))
        try:
            m3 = c.on_server_hello(m2w)
            tr.decisions.append(Decision("C2", True, guard))
        except QCEError as exc:
            tr.decisions.append(Decision("C2", False, guard, type(exc).__name__))
            return tr, wire
        wire.append(m3)
        ct, mac_c = parse(m3, 3, 2)
        th_c = H(m1, m2w, ct)
        kc = keys_from(sp.k_client + qk, th_c)
        tr.events.append(("ClientFinishSent", SERVER, th_c, kc["c2s"]))
        m3w = _apply(plan, 3, m3)
        if m3w is None:
            return tr, wire

        # ---- S2: el servidor recibe ClientFinish
        sp.k_server = None
        f3 = parse(m3w, 3, 2)
        try:
            m4, srv_sess = srv.on_client_finish(m3w)
            accepted, err = True, ""
        except QCEError as exc:
            accepted, err = False, type(exc).__name__
        guard_s: bool | None = None
        if f3 is not None and sp.k_server is not None:
            th_s = H(m1w, m2, f3[0])
            ks = keys_from(sp.k_server + qk, th_s)
            guard_s = hmac.compare_digest(f3[1], mac(ks["ck"], b"client" + th_s))
        tr.decisions.append(Decision("S2", accepted, guard_s if guard_s is not None else False, err))
        if not accepted:
            return tr, wire
        tr.events.append(("ServerDone", SERVER, th_s, ks["c2s"], _offered(m1w), _suite(m2)))
        wire.append(m4)
        m4w = _apply(plan, 4, m4)
        if m4w is None:
            return tr, wire

        # ---- C3: el cliente recibe ServerFinish
        f4 = parse(m4w, 4, 1)
        guard_c = bool(f4) and hmac.compare_digest(f4[0], mac(kc["ck"], b"server" + th_c + mac_c))
        try:
            cs = c.on_server_finish(m4w)
            tr.decisions.append(Decision("C3", True, guard_c))
        except QCEError as exc:
            tr.decisions.append(Decision("C3", False, guard_c, type(exc).__name__))
            return tr, wire
        tr.events.append(("ClientDone", SERVER, th_c, kc["c2s"], kc["s2c"], _offered(m1), _suite(m2w), m1, m2w))
        tr.sessions = (cs, srv_sess)
    return tr, wire


# ---- atacantes que el modelo permite (y que por tanto deben funcionar contra el código) --------------------------------------
def attack_ltk_revealed(ident: HybridSigPrivateKey, policy: Policy) -> Trace:
    """≈ Ed25519 + ML-DSA rotos: con la identidad del servidor, el atacante hace de servidor sin que el servidor real participe."""
    tr = Trace(scenario="LTK revelada antes")
    tr.events.append(("RevealLTK", SERVER))
    c = S.ClientHandshake(ident.public_bytes, policy)
    m1 = c.start()
    tr.events.append(("ClientStart", SERVER, parse(m1, 1, 4)[1]))
    _, nonce_c, offered, qid = parse(m1, 1, 4)
    suite = policy.select(offered.decode().split(",")).encode()
    kem = HybridKemPrivateKey.generate()
    nonce_s = bytes(range(32))
    signed = H(m1, suite, nonce_s, kem.public_bytes, hashlib.sha256(ident.public_bytes).digest())
    m2 = pack(2, [suite, nonce_s, kem.public_bytes, ident.sign(signed, CTX)])
    m3 = c.on_server_hello(m2)
    ct, mac_c = parse(m3, 3, 2)
    th = H(m1, m2, ct)
    secret = kem.decapsulate(ct)
    k = keys_from(secret, th)
    tr.events.append(("ClientFinishSent", SERVER, th, k["c2s"]))
    cs = c.on_server_finish(pack(4, [mac(k["ck"], b"server" + th + mac_c)]))
    tr.events.append(("ClientDone", SERVER, th, k["c2s"], k["s2c"], offered, suite, m1, m2))
    tr.adversary_keys = {k["c2s"], k["s2c"]}
    tr.sessions = (cs, None)
    return tr


def attack_ephemeral_kem_leaked(ident: HybridSigPrivateKey, policy: Policy) -> Trace:
    """≈ X25519 + ML-KEM rotos: con la clave KEM efímera del servidor, el atacante deriva las claves y termina al cliente él solo."""
    tr = Trace(scenario="KEM efímera filtrada (≈ X25519+ML-KEM rotos)")
    qk = b""
    with _Spies() as sp:
        c = S.ClientHandshake(ident.public_bytes, policy)
        srv = S.ServerHandshake(ident, policy)
        m1 = c.start()
        tr.events.append(("ClientStart", SERVER, parse(m1, 1, 4)[1]))
        m2 = srv.on_client_hello(m1)  # el servidor real firma un Hello auténtico
        tr.events.append(("ServerStart", SERVER, m1, m2))
        leaked = sp.leaked_ephemeral[-1]  # lo que un ordenador cuántico podría calcular desde kem_pk
        m3 = c.on_server_hello(m2)
        ct, mac_c = parse(m3, 3, 2)
        th = H(m1, m2, ct)
        tr.events.append(("ClientFinishSent", SERVER, th, keys_from(sp.k_client, th)["c2s"]))
        k = keys_from(leaked.decapsulate(ct), th)  # el atacante, sin el servidor, llega al mismo secreto
        cs = c.on_server_finish(pack(4, [mac(k["ck"], b"server" + th + mac_c)]))
        tr.events.append(("ClientDone", SERVER, th, k["c2s"], k["s2c"], _offered(m1), _suite(m2), m1, m2))
        tr.adversary_keys = {k["c2s"], k["s2c"]}
        tr.sessions = (cs, None)
    return tr


# ---- lemas del modelo como predicados sobre trazas ---------------------------------------------------------------------------
def _idx(tr: Trace, name: str) -> list[tuple[int, tuple]]:
    return [(i, e) for i, e in enumerate(tr.events) if e[0] == name]


def check_lemmas(tr: Trace, expect_secrecy: bool = True) -> list[str]:
    """Devuelve las violaciones de los lemas del modelo en esta traza (vacío = la traza es coherente con el modelo)."""
    bad = []
    reveal = [i for i, _ in _idx(tr, "RevealLTK")]
    for i, (_, S_, th, k1, k2, o, s, m1, m2) in [(i, e) for i, e in _idx(tr, "ClientDone")]:
        revealed_before = any(r < i for r in reveal)
        sd = [j for j, e in _idx(tr, "ServerDone") if j < i and e[1:] == (S_, th, k1, o, s)]
        ss = [j for j, e in _idx(tr, "ServerStart") if j < i and e[1:] == (S_, m1, m2)]
        dupes = [j for j, e in _idx(tr, "ClientDone") if j != i and e[1] == S_ and e[2] == th and e[3] == k1]
        if not revealed_before:
            if not sd:
                bad.append("acuerdo: ClientDone sin un ServerDone previo con el mismo transcript, clave, ofertas y suite")
            if dupes:
                bad.append("acuerdo inyectivo: dos ClientDone con el mismo transcript")
            if not ss:
                bad.append("la firma no liga los Hello: ClientDone sin un ServerStart con el mismo m1 y m2")
        if expect_secrecy and not revealed_before and ({k1, k2} & tr.adversary_keys):
            bad.append("secreto: el atacante conoce una clave de sesión sin que se revelara la identidad")
    return bad


def check_decisions(tr: Trace) -> list[str]:
    """El código no puede aceptar donde la guarda independiente del modelo no se cumple. Rechazar de más solo se admite por
    controles propios del código que el modelo abstrae (política de suites, longitudes, formato)."""
    bad = []
    for d in tr.decisions:
        if d.accepted and d.guard is False:
            bad.append(f"{d.step}: el código ACEPTA y la guarda del modelo NO se cumple (más permisivo que el modelo)")
        if (not d.accepted) and d.guard is True and d.error not in ("PolicyViolation", "MalformedMessage"):
            bad.append(f"{d.step}: el código rechaza algo que el modelo acepta, por un motivo no explicado ({d.error})")
    return bad


def honest_order_ok(tr: Trace) -> bool:
    names = [e[0] for e in tr.events]
    return names == ["ClientStart", "ServerStart", "ClientFinishSent", "ServerDone", "ClientDone"]


def random_plan(rng, pool: dict[int, list[bytes]]) -> Plan:
    """Por mensaje: 80 % pasa; 10 % un byte alterado; 4 % se descarta; 6 % se sustituye por un mensaje de otra sesión."""
    plan: Plan = {}
    for pos in (1, 2, 3, 4):
        r = rng.random()
        if r < 0.80:
            continue
        if r < 0.90:
            plan[pos] = ("flip", rng.randrange(1, 10_000))
        elif r < 0.94:
            plan[pos] = ("drop",)
        elif pool.get(pos):
            plan[pos] = ("replace", rng.choice(pool[pos]))
    return plan
