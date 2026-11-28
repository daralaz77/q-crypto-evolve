"""Segundo lector del sobre sellado, escrito SIGUIENDO docs/SEALED_ENVELOPE_SPEC.md, sin importar `qce`: solo la biblioteca estándar y `cryptography`.

Sirve para comprobar que la especificación y el código dicen lo mismo. LÍMITE: lo escribió la misma instancia que el código, así que no es una implementación
independiente de verdad (comparte posibles malentendidos) y usa las mismas primitivas."""
import base64
import hashlib
import hmac
import json
import math
import struct
import unicodedata

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa, mlkem, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

LEVELS = {"standard": {"kem": "X-Wing-draft11", "kem_pk": 1216, "ct": 1120, "sig_pk": 1984, "sig": 3373, "mldsa": mldsa.MLDSA65PublicKey},
          "high": {"kem": "QCE-X25519-MLKEM1024", "kem_pk": 1600, "ct": 1600, "sig_pk": 2624, "sig": 4691, "mldsa": mldsa.MLDSA87PublicKey}}
CHUNK = 65536


class Rejected(Exception):
    pass


def need(cond, why):
    if not cond:
        raise Rejected(why)


def u32(n):
    return struct.pack(">I", n)


def lp(x):
    return u32(len(x)) + x


def H(*parts):
    return hashlib.sha256(b"".join(lp(p) for p in parts)).digest()


def hkdf(ikm, info):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(ikm)


def raw(public_key):
    return public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)


def b64(s, n):
    need(isinstance(s, str), "base64")
    b = base64.b64decode(s.encode("ascii"), validate=True)
    need(len(b) == n and base64.b64encode(b).decode() == s, "base64 no canónico o longitud")
    return b


def obj(raw_bytes, fields):
    def pairs(p):
        need(len(dict(p)) == len(p), "clave repetida")
        return dict(p)
    o = json.loads(raw_bytes.decode("utf-8"), object_pairs_hook=pairs)
    need(isinstance(o, dict) and set(o) == set(fields), "campos")
    return o


def integer(v, lo, hi):
    need(type(v) is int and lo <= v <= hi, "entero fuera de rango")
    return v


def printable(s, hi):
    return isinstance(s, str) and 1 <= len(s) <= hi and all(c == " " or unicodedata.category(c)[0] not in "CZ" for c in s)


# ------------------------------------------------------------------- KEM y firma (sección 2)
def kem_private(level, seed):
    if level == "standard":
        need(len(seed) == 32, "semilla X-Wing")
        e = hashlib.shake_256(seed).digest(96)
        m, x = mlkem.MLKEM768PrivateKey.from_seed_bytes(e[:64]), x25519.X25519PrivateKey.from_private_bytes(e[64:])
        pk = m.public_key().public_bytes_raw() + raw(x.public_key())

        def decap(ct):
            ct_m, ct_x = ct[:1088], ct[1088:]
            ss_x = x.exchange(x25519.X25519PublicKey.from_public_bytes(ct_x))
            return hashlib.sha3_256(m.decapsulate(ct_m) + ss_x + ct_x + pk[1184:] + bytes.fromhex("5c2e2f2f5e5c")).digest()
        return pk, decap
    need(len(seed) == 96, "semilla híbrida")
    x, m = x25519.X25519PrivateKey.from_private_bytes(seed[:32]), mlkem.MLKEM1024PrivateKey.from_seed_bytes(seed[32:])
    pk = raw(x.public_key()) + m.public_key().public_bytes_raw()

    def decap(ct):
        ss_x = x.exchange(x25519.X25519PublicKey.from_public_bytes(ct[:32]))
        return hkdf(m.decapsulate(ct[32:]) + ss_x, b"QCE1/hybrid-kem/X25519+ML-KEM-1024" + ct + pk)
    return pk, decap


def verify(level, pk, context, message, sig):
    p = LEVELS[level]
    need(len(pk) == p["sig_pk"] and len(sig) == p["sig"], "longitud de firma")
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(pk[:32]).verify(sig[:64], context + b"\x00" + message)
        p["mldsa"].from_public_bytes(pk[32:]).verify(sig[64:], message, context)
    except Exception as exc:
        raise Rejected("firma inválida") from exc


# ------------------------------------------------------------------- Shamir (sección 4), con tablas de logaritmos
EXP, LOG = [0] * 510, [0] * 256
_v = 1
for _i in range(255):
    EXP[_i], LOG[_v] = _v, _i
    _v ^= (_v << 1) ^ (0x11B if _v & 0x80 else 0)          # multiplicar por el generador 3
    _v &= 0xFF
for _i in range(255, 510):
    EXP[_i] = EXP[_i - 255]


def recover(points):
    xs = list(points)
    out = bytearray(32)
    for xi in xs:
        lw = sum(LOG[xj] - LOG[xj ^ xi] for xj in xs if xj != xi) % 255
        for i, y in enumerate(points[xi]):
            if y:
                out[i] ^= EXP[(LOG[y] + lw) % 255]
    return bytes(out)


# ------------------------------------------------------------------- archivo (secciones 3, 5, 6, 7, 8)
def read_file(blob, sender_pk):
    stub = blob[:8] == b"QSELSTUB"
    if stub:
        blob = blob[8:]
    need(blob[:6] == bytes.fromhex("5153454c0300"), "magia")
    level = next((name for name, p in LEVELS.items() if len(sender_pk) == p["sig_pk"]), None)
    need(level is not None, "clave de emisor")
    p = LEVELS[level]
    n = struct.unpack(">I", blob[6:10])[0]
    need(2 <= n <= 1048576 and len(blob) >= 10 + n + 2 * p["sig"] + 16, "longitudes")
    prefix, head_sig = blob[:10 + n], blob[10 + n:10 + n + p["sig"]]
    rest, file_sig = blob[10 + n + p["sig"]:-p["sig"]], blob[-p["sig"]:]
    verify(level, sender_pk, b"QSEL3/header", prefix, head_sig)
    d = hashlib.sha256(prefix).digest()
    if stub:                                                  # sección 3.2: huella y longitud del cuerpo en lugar del cuerpo
        need(len(rest) == 40 and struct.unpack(">Q", rest[32:])[0] >= 16, "resguardo")
        body, body_hash, length = None, rest[:32], rest[32:]
    else:
        body, body_hash, length = rest, hashlib.sha256(rest).digest(), struct.pack(">Q", len(rest))
    verify(level, sender_pk, b"QSEL3/file", d + body_hash + length, file_sig)
    version = json.loads(prefix[10:].decode("utf-8")).get("v")
    hidden = version == 5                                              # sección 3.3: modo discreto
    h = obj(prefix[10:], ["v", "level", "kem", "aead", "sid", "sender", "openers", "need", "groups", "commit", "locks"] + (["saltcom"] if hidden else []))
    need(type(h["v"]) is int and h["v"] in (3, 4, 5) and h["level"] == level and h["kem"] == p["kem"], "versión, nivel o KEM")
    need(h["sender"] == hashlib.sha256(sender_pk).hexdigest() and h["aead"] in ("AES-256-GCM", "CHACHA20-POLY1305"), "emisor o AEAD")
    need(1 <= len(h["openers"]) <= 8 and 1 <= len(h["groups"]) <= 8, "listas")
    integer(h["need"], 1, len(h["groups"]))
    need(isinstance(h["locks"], list) and len(h["locks"]) <= 4, "candados")
    for k in h["locks"]:
        need(set(k) == {"id", "label", "com"} | ({"salt"} if hidden else set()) and len(bytes.fromhex(k["id"])) == 16 and printable(k["label"], 64), "candado")
    need(len({k["id"] for k in h["locks"]}) == len(h["locks"]), "candado repetido")
    seen = set()
    for g in h["groups"]:
        need(set(g) == {"name", "k", "com", "members"} and printable(g["name"], 64) and 1 <= len(g["members"]) <= 16, "grupo")
        integer(g["k"], 1, len(g["members"]))
        for m in g["members"]:
            need(set(m) == {"id", "ct", "box", "com"} and m["id"] not in seen, "miembro")
            b64(m["box"], 80 if hidden else 48)
            seen.add(m["id"])
    return {"level": level, "p": p, "h": h, "D": d, "body": body, "body_hash": body_hash, "hidden": hidden}


def policy_digest(h):
    """Sección 4.1: la cabecera sin los `ct` ni los `box`, en JSON canónico."""
    bare = json.loads(json.dumps(h))
    for g in bare["groups"]:
        g["members"] = [{"id": m["id"], "com": m["com"]} for m in g["members"]]
    return H(b"QSEL3/policy", json.dumps(bare, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode())


def lock_header_id(hidden, sid, lock_id):
    return (H(b"QSEL3/blind-lock", sid, lock_id)[:16] if hidden else lock_id).hex()


def lock_salt(f, entry_id, file_key):
    """Sección 3.3: la sal que la entrada de un candado lleva para su guardián."""
    sid = bytes.fromhex(f["h"]["sid"])
    entry = next(k for k in f["h"]["locks"] if k["id"] == entry_id)
    key = hkdf(file_key, lp(b"QSEL3/blind-salt-key") + lp(sid))
    return AESGCM(key).decrypt(bytes(12), b64(entry["salt"], 48), bytes.fromhex(entry_id))


def padded_size(n):
    """Sección 3.3: Padmé con un mínimo de 4096."""
    if n <= 4096:
        return 4096
    e = int(math.floor(math.log2(n)))
    z = e - (int(math.floor(math.log2(e))) + 1)
    return ((n + (1 << z) - 1) >> z) << z


def read_request(f, blob, now=None, salt=None):
    r = obj(blob, ["v", "file", "kem", "signer", "reason", "issued", "expires", "nonce", "sig"])
    p = f["p"]
    need(type(r["v"]) is int and r["v"] == 4 and r["file"] == f["D"].hex() and printable(r["reason"], 500), "solicitud")
    signer, kem, nonce = b64(r["signer"], p["sig_pk"]), b64(r["kem"], p["kem_pk"]), b64(r["nonce"], 16)
    integer(r["issued"], 0, 2**62)
    integer(r["expires"], r["issued"] + 1, r["issued"] + 604800)
    who, h = hashlib.sha256(signer).digest(), f["h"]
    if f["hidden"]:
        sid = bytes.fromhex(h["sid"])
        need(salt is not None and H(b"QSEL3/blind-salt", sid, salt).hex() == h["saltcom"], "sal")
        who = H(b"QSEL3/blind-opener", sid, salt, who)
    need(who.hex() in h["openers"], "solicitante no autorizado")
    message = b"".join(lp(v) for v in (f["D"], kem, signer, r["reason"].encode(), struct.pack(">Q", r["issued"]), struct.pack(">Q", r["expires"]), nonce))
    verify(f["level"], signer, b"QSEL3/request", message, b64(r["sig"], p["sig"]))
    need(now is None or r["issued"] - 300 <= now <= r["expires"], "solicitud fuera de plazo")
    return hashlib.sha256(message).digest()


def open_file(blob, sender_pk, opener_seed, contributions, tokens=()):
    """Devuelve (claro, intermedios). Lanza Rejected si algo no cumple la especificación o no hay quórum."""
    f = read_file(blob, sender_pk)
    need(f["body"] is not None, "un resguardo no se puede abrir")
    h, p, sid = f["h"], f["p"], bytes.fromhex(f["h"]["sid"])
    opener_pk, decap = kem_private(f["level"], opener_seed)
    given = {}
    for t_blob in tokens:
        t = obj(t_blob, ["v", "file", "id", "key"])
        need(type(t["v"]) is int and t["v"] == 3 and t["file"] == f["D"].hex(), "ficha de otro archivo")
        entry = next((k for k in h["locks"] if k["id"] == t["id"]), None)
        need(entry is not None, "ficha de un candado ajeno")
        key = b64(t["key"], 32)
        need(H(b"QSEL3/lock", sid, bytes.fromhex(t["id"]), key).hex() == entry["com"], "ficha falsa")
        given[t["id"]] = key
    need(all(k["id"] in given for k in h["locks"]), "falta una ficha de candado")
    lock_keys = b"".join(given[k["id"]] for k in h["locks"])
    shares = {}
    for c_blob in contributions:
        c = obj(c_blob, ["v", "file", "g", "x", "ct", "box"])
        need(type(c["v"]) is int and c["v"] == 3 and c["file"] == f["D"].hex(), "contribución")
        g = integer(c["g"], 1, len(h["groups"]))
        x = integer(c["x"], 1, len(h["groups"][g - 1]["members"]))
        ctx = lp(b"QSEL3/contrib") + lp(f["D"]) + lp(u32(g)) + lp(u32(x)) + lp(hashlib.sha256(opener_pk).digest())
        s = AESGCM(hkdf(decap(b64(c["ct"], p["ct"])), ctx)).decrypt(bytes(12), b64(c["box"], 48), ctx)
        need(H(b"QSEL3/share", sid, u32(g), u32(x), s).hex() == h["groups"][g - 1]["members"][x - 1]["com"], "participación falsa")
        shares[(g, x)] = s
    group_secrets = {}
    for g, group in enumerate(h["groups"], start=1):
        mine = {x: s for (gg, x), s in sorted(shares.items()) if gg == g}
        if len(mine) >= group["k"]:
            s_g = recover({x: mine[x] for x in sorted(mine)[-group["k"]:]})   # a propósito, OTRO subconjunto que el lector principal
            need(H(b"QSEL3/group", sid, u32(g), s_g).hex() == group["com"], "reparto inconsistente")
            group_secrets[g] = s_g
    need(len(group_secrets) >= h["need"], "quórum insuficiente")
    K = recover({g: group_secrets[g] for g in sorted(group_secrets)[-h["need"]:]})
    need(H(b"QSEL3/key", sid, K).hex() == h["commit"], "clave inconsistente")
    payload_key = hkdf(K + lock_keys, lp(b"QSEL3/payload") + lp(f["D"]))
    aead = (AESGCM if h["aead"] == "AES-256-GCM" else ChaCha20Poly1305)(payload_key)
    body, out, i = f["body"], bytearray(), 0
    while True:
        piece, body = body[:CHUNK + 16], body[CHUNK + 16:]
        last = not body
        out += aead.decrypt(i.to_bytes(11, "big") + (b"\x01" if last else b"\x00"), piece, None)
        if last:
            break
        i += 1
    if f["hidden"]:
        need(len(out) >= 8, "relleno")
        real = struct.unpack(">Q", out[:8])[0]
        need(real <= len(out) - 8 and not any(out[8 + real:]) and len(out) == padded_size(real + 8), "relleno")
        out = out[8: 8 + real]
    return bytes(out), {"header_digest": f["D"], "shares": shares, "group_secrets": group_secrets, "secret": K, "payload_key": payload_key}


def lock_file_key(master, sid):
    """Sección 5: la clave por archivo que el guardián deriva de la clave maestra."""
    return hkdf(master, lp(b"QSEL3/lock-file") + lp(sid))


def keeper_proof(master, lock_id, requester_fingerprint, request_ident):
    """Sección 10: la prueba simétrica con la que un solicitante dado de alta acompaña su solicitud ante el guardián."""
    shared = hkdf(master, lp(b"QSEL3/keeper-requester") + lp(lock_id) + lp(requester_fingerprint))
    return shared, hmac.new(shared, lp(b"QSEL3/keeper-proof") + lp(request_ident), hashlib.sha256).digest()


def join_lock(parts, lock_id, commitments, master_commitment):
    """Sección 11: reconstruye la maestra de un candado a partir de `{x: parte}` y comprueba los compromisos."""
    for x, share in parts.items():
        need(H(b"QSEL3/lock-share", lock_id, u32(x), share).hex() == commitments[x - 1], "parte falsa")
    key = recover(parts)
    need(H(b"QSEL3/lock-master", lock_id, key).hex() == master_commitment, "maestra inconsistente")
    return key


def member_wrap(blob, sender_pk, g, x, seed):
    """Intermedios de la sección 4 para un custodio: (secreto KEM, clave de envoltura, participación)."""
    return unwrap(blob, sender_pk, g, x, seed)[:3]


def unwrap(blob, sender_pk, g, x, seed):
    """(secreto KEM, clave de envoltura, participación, sal) del hueco (g, x); la sal va vacía fuera del modo discreto."""
    f = read_file(blob, sender_pk)
    h, sid = f["h"], bytes.fromhex(f["h"]["sid"])
    pk, decap = kem_private(f["level"], seed)
    m = h["groups"][g - 1]["members"][x - 1]
    ss = decap(b64(m["ct"], f["p"]["ct"]))
    own = hkdf(ss, lp(b"QSEL3/blind-id") + lp(sid)) if f["hidden"] else hashlib.sha256(pk).digest()
    need(own.hex() == m["id"], "la clave no es de ese custodio")
    context = [sid, u32(g), u32(x), bytes.fromhex(m["id"]), bytes.fromhex(h["sender"])]
    if h["v"] == 3:
        context = [b"QSEL3/wrap"] + context
    else:                                                              # sección 4.1: atada a la política
        context = [b"QSEL3/wrap-policy"] + context + [policy_digest(h)]
    wk = hkdf(ss, b"".join(lp(v) for v in context))
    plain = AESGCM(wk).decrypt(bytes(12), b64(m["box"], 80 if f["hidden"] else 48), bytes.fromhex(m["com"]))
    return ss, wk, plain[:32], plain[32:]
