"""Conformidad modelo-código de QIL1: trazas del CÓDIGO REAL (con un atacante activo) contra el modelo formal (formal/qil1.spthy).

Qué hace
  1. `tests/qkd_layer_scenarios.py conformance` ejecuta, en un proceso nuevo, sesiones TLS 1.3 reales con el código de `qkd_layer`
     (honesta, reutilización, atacante que conoce el id, cliente con clave equivocada, MITM con certificado falso) y devuelve, por sesión,
     los mensajes que cada extremo envió y recibió, el valor de ligadura y el certificado que vio cada extremo, y las llamadas que el servidor
     hizo a su fuente de claves (reserve/commit/release).
  2. Este módulo, con código INDEPENDIENTE escrito solo a partir de docs/QKD_LAYER_SPEC.md (no importa `qkd_layer`), recalcula `th`, las
     etiquetas y las claves y convierte cada sesión en EVENTOS con los nombres del modelo: ClientStart, ServerStart, ServerAbort, ServerDone,
     ClientDone.
  3. Comprueba sobre esas trazas las fórmulas de los lemas (acuerdo, ligadura al canal, acuerdo del servidor, autenticación por la clave,
     reserva exclusiva, sin reutilización tras completar).
  4. Comprueba las DECISIONES: el código solo puede aceptar si la guarda independiente (las comprobaciones `Eq` del modelo) se cumple.
     Puede ser MÁS estricto, nunca más permisivo; y un cliente o servidor honesto con guarda válida DEBE aceptar.

Qué NO hace: no demuestra el código ni las primitivas, ni cubre la capa de registros; solo que las trazas observadas son trazas del modelo.
"""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def lp(x: bytes) -> bytes:
    return len(x).to_bytes(4, "big") + x


def th_of(bind: bytes, cert: bytes, kid: bytes, nc: bytes, ns: bytes) -> bytes:
    return hashlib.sha256(lp(b"QIL1/th") + lp(bind) + lp(hashlib.sha256(cert).digest()) + lp(kid) + lp(nc) + lp(ns)).digest()


def hk(key: bytes, th: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=th, info=info).derive(key)


def mac(k: bytes, m: bytes) -> bytes:
    return hmac.new(k, m, hashlib.sha256).digest()


@dataclass
class Trace:
    events: list[tuple] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)


def hello_parts(frame: bytes):
    """HELLO bien formado → (kid, nc); si no, None (misma forma que la especificación §5)."""
    if len(frame) < 5 or frame[:4] != b"QIL1":
        return None
    n = frame[4]
    if not 1 <= n <= 128 or len(frame) != 5 + n + 32:
        return None
    return frame[5:5 + n], frame[5 + n:]


def analyse(sessions: list[dict]) -> Trace:
    """Convierte las sesiones observadas en eventos del modelo y comprueba guardas. Cada sesión:
       name, key (hex, la del CLIENTE), kid, client{outcome, bind, cert, sent[], recv[]}, server{outcome, bind, cert, sent[], recv[], calls[]}."""
    tr = Trace()
    state: dict[bytes, str] = {}   # estado de cada clave en el SERVIDOR: available | reserved | consumed
    server_keys: dict[bytes, bytes] = {}
    PHASE = {"ClientStart": 0, "ServerStart": 1, "ClientDone": 2, "ServerDone": 3, "ServerAbort": 3}   # orden causal dentro de una sesión
    for s in sessions:
        first = len(tr.events)
        for kid_hex, key_hex in s.get("server_keys", {}).items():
            server_keys[bytes.fromhex(kid_hex)] = bytes.fromhex(key_hex)
            state.setdefault(bytes.fromhex(kid_hex), "available")
        ck = bytes.fromhex(s["key"])
        name = s["name"]
        c, sv = s["client"], s["server"]
        # ---------------- cliente ----------------
        if c["sent"]:
            kid_c, nc = hello_parts(bytes.fromhex(c["sent"][0])) or (None, None)
            if kid_c is None:
                tr.problems.append(f"{name}: el cliente envió un HELLO mal formado")
            else:
                tr.events.append(("ClientStart", name, kid_c, nc))
                if c["recv"]:
                    acc = bytes.fromhex(c["recv"][0])
                    if len(acc) == 64:
                        ns, ts = acc[:32], acc[32:]
                        b_c, cert_c = bytes.fromhex(c["bind"]), bytes.fromhex(c["cert"])
                        th = th_of(b_c, cert_c, kid_c, nc, ns)
                        conf = hk(ck, th, b"QIL1/conf")
                        guard = hmac.compare_digest(ts, mac(conf, b"server" + th))
                        done = c["outcome"] == "ok"
                        if done and not guard:
                            tr.problems.append(f"{name}: el cliente aceptó sin que la guarda del modelo se cumpla (más permisivo que el modelo)")
                        if guard and not done:
                            tr.problems.append(f"{name}: la guarda se cumple y el cliente no aceptó")
                        if guard:
                            tr.events.append(("ClientDone", name, kid_c, th, hk(ck, th, b"QIL1/c2s"), hk(ck, th, b"QIL1/s2c"), b_c, hashlib.sha256(cert_c).digest()))
                            expect_confirm = mac(conf, b"client" + th + ts)
                            if not c["sent"][1:] or bytes.fromhex(c["sent"][1]) != expect_confirm:
                                tr.problems.append(f"{name}: la etiqueta del cliente no es la del modelo")
                    elif c["outcome"] == "ok":
                        tr.problems.append(f"{name}: el cliente aceptó un ACCEPT de longitud {len(acc)}")
                elif c["outcome"] == "ok":
                    tr.problems.append(f"{name}: el cliente terminó sin recibir ACCEPT")
        # ---------------- servidor ----------------
        calls = sv["calls"]
        parts = hello_parts(bytes.fromhex(sv["recv"][0])) if sv["recv"] else None
        if parts is None:
            if calls:
                tr.problems.append(f"{name}: el servidor tocó su fuente de claves con un HELLO mal formado")
        else:
            kid_s, nc_s = parts
            reserved = any(c_[0] == "reserve" and c_[2] for c_ in calls)
            expect_reserve = state.get(kid_s) == "available"
            if reserved != expect_reserve:
                tr.problems.append(f"{name}: reserva {reserved} y el modelo esperaba {expect_reserve} (estado {state.get(kid_s)})")
            if reserved:
                if not sv["sent"]:
                    tr.problems.append(f"{name}: reservada la clave y sin ACCEPT")
                else:
                    acc = bytes.fromhex(sv["sent"][0])
                    ns, ts = acc[:32], acc[32:]
                    b_s, cert_s = bytes.fromhex(sv["bind"]), bytes.fromhex(sv["cert"])
                    ks = server_keys[kid_s]
                    th = th_of(b_s, cert_s, kid_s, nc_s, ns)
                    conf = hk(ks, th, b"QIL1/conf")
                    if not hmac.compare_digest(ts, mac(conf, b"server" + th)):
                        tr.problems.append(f"{name}: el ACCEPT del servidor no es el del modelo")
                    tr.events.append(("ServerStart", name, kid_s, th, b_s, hashlib.sha256(cert_s).digest()))
                    state[kid_s] = "reserved"
                    guard = bool(sv["recv"][1:]) and hmac.compare_digest(bytes.fromhex(sv["recv"][1]), mac(conf, b"client" + th + ts))
                    committed = any(c_[0] == "commit" for c_ in calls)
                    released = any(c_[0] == "release" for c_ in calls)
                    if committed and not guard:
                        tr.problems.append(f"{name}: el servidor consumió la clave sin que la guarda del cliente se cumpla")
                    if guard and not committed:
                        tr.problems.append(f"{name}: la guarda se cumple y el servidor no completó")
                    if committed == released:
                        tr.problems.append(f"{name}: tras reservar debe haber exactamente un commit o un release")
                    if committed:
                        tr.events.append(("ServerDone", name, kid_s, th, hk(ks, th, b"QIL1/c2s"), hk(ks, th, b"QIL1/s2c"), b_s, hashlib.sha256(cert_s).digest()))
                        state[kid_s] = "consumed"
                    else:
                        tr.events.append(("ServerAbort", name, kid_s, th))
                        state[kid_s] = "available"
        tr.events[first:] = sorted(tr.events[first:], key=lambda e: PHASE[e[0]])
    check_lemmas(tr)
    return tr


def check_lemmas(tr: Trace) -> None:
    ev = tr.events
    idx = {e: i for i, e in enumerate(ev)}
    starts = [e for e in ev if e[0] == "ServerStart"]
    dones_s = [e for e in ev if e[0] == "ServerDone"]
    dones_c = [e for e in ev if e[0] == "ClientDone"]
    aborts = [e for e in ev if e[0] == "ServerAbort"]
    cstarts = [e for e in ev if e[0] == "ClientStart"]
    # agreement / channel_agreement: ClientDone(kid, th, b, ch) ⇒ antes hubo ServerStart con el mismo kid, th, b y huella
    for d in dones_c:
        if not any(s[2] == d[2] and s[3] == d[3] and s[4] == d[6] and s[5] == d[7] and idx[s] < idx[d] for s in starts):
            tr.problems.append(f"LEMA channel_agreement violado en {d[1]}: el cliente terminó sin un ServerStart en su misma sesión TLS")
    # server_agreement: ServerDone ⇒ antes un ClientDone con las mismas claves y la misma sesión
    for d in dones_s:
        if not any(c[2] == d[2] and c[3] == d[3] and c[4] == d[4] and c[5] == d[5] and c[6] == d[6] and c[7] == d[7] and idx[c] < idx[d] for c in dones_c):
            tr.problems.append(f"LEMA server_agreement violado en {d[1]}")
    # client_authenticated_by_qkd: ServerDone ⇒ antes un ClientStart con ese kid
    for d in dones_s:
        if not any(c[2] == d[2] and idx[c] < idx[d] for c in cstarts):
            tr.problems.append(f"LEMA client_authenticated_by_qkd violado en {d[1]}")
    # key_single_use: dos ServerStart del mismo kid ⇒ un ServerAbort del primero entre medias
    for i, a in enumerate(starts):
        for b in starts[i + 1:]:
            if a[2] == b[2] and not any(x[2] == a[2] and x[3] == a[3] and idx[a] < idx[x] < idx[b] for x in aborts):
                tr.problems.append(f"LEMA key_single_use violado: {a[1]} y {b[1]}")
    # no_reuse_after_done: ningún ServerStart tras un ServerDone del mismo kid
    for d in dones_s:
        if any(s[2] == d[2] and idx[s] > idx[d] for s in starts):
            tr.problems.append(f"LEMA no_reuse_after_done violado tras {d[1]}")
