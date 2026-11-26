"""Línea de comandos del sobre sellado: `python -m qce.sealed <comando>` (o `qce-sello`). Los secretos se guardan cifrados; la frase se pide por terminal (o se lee
de `--passphrase-file`, que NO debe ser legible por otros). Ceremonia completa en docs/SEALED_ENVELOPE.md."""
from __future__ import annotations

import argparse
import getpass
import json
import sys
import time
from pathlib import Path

from ..core.atomic import atomic_write
from ..core.errors import PolicyViolation, QCEError
from ..pqc.hybrid import LEVELS, HybridSigPrivateKey
from . import envelope, keeper, keys, lockshare


def _passphrase(a, path: Path, new: bool = False) -> str:
    if a.passphrase_file:
        f = Path(a.passphrase_file)
        if f.stat().st_mode & 0o077:
            raise PolicyViolation(f"{f} es legible por otros usuarios (chmod 600)")
        return f.read_text(encoding="utf-8").rstrip("\n")
    phrase = getpass.getpass(f"Frase para {path.name}: ")
    if new and getpass.getpass("Repítela: ") != phrase:
        raise PolicyViolation("las frases no coinciden")
    return phrase


def _signing_key(a, path: str) -> HybridSigPrivateKey:
    meta, seed = keys.load_secret(path, keys.EMISOR, _passphrase(a, Path(path)))
    return HybridSigPrivateKey.from_seed(seed, LEVELS[meta["level"]])


def _custody_key(a, path: str):
    meta, seed = keys.load_secret(path, keys.CUSTODIO, _passphrase(a, Path(path)))
    return envelope.SUITES[meta["level"]].from_seed(seed)


def _load_lock(a, path: str) -> envelope.Lock:
    meta, key = keys.load_secret(path, "candado", _passphrase(a, Path(path)))
    return envelope.Lock(bytes.fromhex(meta["extra"]["id"]), meta["extra"]["label"], key)


def _load_share(a, path: str) -> lockshare.LockShare:
    meta, share = keys.load_secret(path, "parte", _passphrase(a, Path(path)))
    x = meta["extra"]
    return lockshare.LockShare(bytes.fromhex(x["id"]), x["label"], x["k"], x["x"], share, tuple(x["commitments"]), x["master"])


def _lock_from(a) -> envelope.Lock:
    if bool(a.lock) == bool(a.share):
        raise PolicyViolation("indica --lock o varias --share (una de las dos cosas)")
    return _load_lock(a, a.lock) if a.lock else lockshare.join_lock([_load_share(a, p) for p in a.share])


def _pin(text: str | None):
    if text is None:
        return None
    count, code = text.split(":", 1)
    return int(count), bytes.fromhex(code)


def _sender(a) -> bytes:
    return keys.load_public(a.sender_pub, keys.EMISOR)


def _show_request(a) -> envelope.Request:
    req = envelope.read_request(envelope.read_header(a.file, _sender(a)), Path(a.request).read_bytes())
    print(f"solicitante autorizado {req.requester[:16]} · motivo: {req.reason} · caduca {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(req.expires))}")
    return req


def _output(path: str, data: bytes, mode: int = 0o600) -> None:
    atomic_write(path, data, mode)
    print(f"escrito {path}")


# ---------------------------------------------------------------------------------------------------------------- comandos
def _keygen(a) -> None:
    if a.kind == "candado":
        path = Path(f"{a.name}.candado")
        lock = envelope.Lock.generate(Path(a.name).name)
        keys.save_secret(path, "candado", lock.key, _passphrase(a, path, new=True), extra={"id": lock.ident.hex(), "label": lock.label})
        print(f"{path} creado. Si se pierde (y no está repartido), los archivos que cierre no se podrán abrir nunca más.")
        return
    key = HybridSigPrivateKey.generate(LEVELS[a.level]) if a.kind == keys.EMISOR else envelope.SUITES[a.level].generate()
    private, public = Path(f"{a.name}.key"), Path(f"{a.name}.pub")
    if public.exists():
        raise PolicyViolation(f"{public} ya existe: no se sobrescribe una clave")
    keys.save_secret(private, a.kind, key.seed(), _passphrase(a, private, new=True), a.level)
    keys.save_public(public, a.kind, a.level, key.public_bytes)
    print(f"{private} (cifrada) y {public}; huella {envelope.fingerprint(key.public_bytes)[:16]}")


def _split_lock(a) -> None:
    lock = _load_lock(a, a.lock)
    for part in lockshare.split_lock(lock, a.k, a.n):
        path = Path(f"{a.out_prefix}-{part.x}.parte")
        extra = {"id": part.ident.hex(), "label": part.label, "k": part.k, "x": part.x, "commitments": list(part.commitments), "master": part.master}
        keys.save_secret(path, "parte", part.share, _passphrase(a, path, new=True), extra=extra)
        print(f"escrito {path}")
    print("Comprueba que las partes reconstruyen y SOLO entonces destruye el archivo del candado completo.")


def _seal(a) -> None:
    groups = []
    for spec in a.group:
        name, k, pubs = spec.split(":", 2)
        groups.append(envelope.Group(name, int(k), tuple(keys.load_public(p, keys.CUSTODIO) for p in pubs.split(","))))
    header = envelope.seal(a.src, a.dst, _signing_key(a, a.sender), groups, [keys.load_public(p, keys.EMISOR) for p in a.opener], a.need,
                           locks=[_load_lock(a, p) for p in a.lock])
    print(json.dumps(header.describe(), indent=1, ensure_ascii=False))


def _info(a) -> None:
    hd, _, length = envelope.verify_file(a.file, _sender(a))
    print(json.dumps({**hd.describe(), "cuerpo_cifrado_bytes": length, "resguardo": hd.stub, "firma": "válida"}, indent=1, ensure_ascii=False))


def _stub(a) -> None:
    _output(a.out, envelope.make_stub(a.file, _sender(a)), 0o644)


def _request(a) -> None:
    blob = envelope.request_open(a.file, _sender(a), _signing_key(a, a.key), keys.load_public(a.to, keys.CUSTODIO), a.reason, a.ttl_hours * 3600)
    _output(a.out, blob, 0o644)


def _contribute(a) -> None:
    key = _custody_key(a, a.key)
    _show_request(a)
    who = keeper.Custodian(key, a.journal or str(Path(a.key).with_suffix(".diario")), anchor=a.anchor, pinned_head=_pin(a.pin))
    _output(a.out, who.contribute(a.file, _sender(a), Path(a.request).read_bytes()))


def _prove(a) -> None:
    req = _show_request(a)
    _, secret = keys.load_secret(a.secret, "secreto", _passphrase(a, Path(a.secret)))
    _output(a.out, keeper.prove(req.ident, secret).hex().encode())


def _guardian(a) -> None:
    who = keeper.Keeper(_lock_from(a), a.journal, anchor=a.anchor, pinned_head=_pin(a.pin))
    if a.op == "register":
        print(f"registrado {who.register(a.file, _sender(a))}")
    elif a.op == "withdraw":
        who.withdraw(envelope.read_header(a.file, _sender(a)).digest.hex())
        print("retirado: no habrá fichas nuevas para ese archivo (las ya emitidas siguen valiendo)")
    elif a.op == "enroll":
        out = Path(a.out)
        if out.exists():
            raise PolicyViolation(f"{out} ya existe")
        phrase = _passphrase(a, out, new=True)
        keys.save_secret(out, "secreto", who.enroll(keys.load_public(a.requester, keys.EMISOR)), phrase)
        print(f"secreto del solicitante en {out}: entrégalo (y su frase, aparte) por canales que no dependan de clave pública")
    elif a.op == "revoke":
        who.revoke(keys.load_public(a.requester, keys.EMISOR))
        print("dado de baja")
    elif a.op == "adopt-anchor":
        who.journal.adopt_anchor()
        print("ancla creada")
    elif a.op == "head":
        count, code = who.journal.head()
        print(f"{count}:{code.hex()}")
    else:
        _show_request(a)
        token = who.release(a.file, _sender(a), Path(a.request).read_bytes(), bytes.fromhex(Path(a.proof).read_text(encoding="ascii").strip()))
        _output(a.out, token)
        print("la ficha es SECRETA: entrégala por un canal que no dependa de clave pública y destrúyela tras usarla")


def _open(a) -> None:
    report = envelope.open_sealed(a.file, a.dst, _sender(a), _custody_key(a, a.key), [Path(p).read_bytes() for p in a.parts],
                                  [Path(p).read_bytes() for p in a.token])
    print(json.dumps(report, indent=1, ensure_ascii=False))


# ---------------------------------------------------------------------------------------------------------------- analizador
def _parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--passphrase-file", help="archivo 0600 con la frase (si no, se pide por terminal)")
    ap = argparse.ArgumentParser(prog="qce-sello", description="Sobre poscuántico con quórum (LABORATORIO: sin revisión externa)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def command(name: str, handler, parent=sub, help_text: str = ""):
        p = parent.add_parser(name, parents=[common], help=help_text)
        p.set_defaults(handler=handler)
        return p

    def about_file(p):
        p.add_argument("file"), p.add_argument("--sender-pub", required=True, help="clave pública del emisor que TÚ ya conoces")

    k = command("keygen", _keygen, help_text="crea una clave")
    k.add_argument("kind", choices=[keys.EMISOR, keys.CUSTODIO, "candado"]), k.add_argument("name"), k.add_argument("--level", choices=sorted(LEVELS), default="standard")
    sp = command("split-lock", _split_lock, help_text="reparte la maestra de un candado k de n")
    sp.add_argument("--lock", required=True), sp.add_argument("--k", type=int, required=True), sp.add_argument("--n", type=int, required=True)
    sp.add_argument("--out-prefix", required=True)
    s = command("seal", _seal, help_text="sella un archivo")
    s.add_argument("src"), s.add_argument("dst"), s.add_argument("--sender", required=True)
    s.add_argument("--opener", action="append", required=True), s.add_argument("--group", action="append", required=True, help="nombre:umbral:pub1,pub2")
    s.add_argument("--need", type=int), s.add_argument("--lock", action="append", default=[])
    about_file(command("info", _info, help_text="verifica y describe"))
    st = command("stub", _stub, help_text="resguardo (sin cuerpo) para custodios y guardián")
    about_file(st), st.add_argument("--out", required=True)
    q = command("request", _request, help_text="pide la apertura")
    about_file(q), q.add_argument("--key", required=True), q.add_argument("--to", required=True), q.add_argument("--reason", required=True)
    q.add_argument("--out", required=True), q.add_argument("--ttl-hours", type=int, default=24)
    c = command("contribute", _contribute, help_text="un custodio entrega su participación")
    about_file(c), c.add_argument("--key", required=True), c.add_argument("--request", required=True), c.add_argument("--out", required=True)
    c.add_argument("--journal"), c.add_argument("--anchor"), c.add_argument("--pin")
    pv = command("prove", _prove, help_text="prueba simétrica para el guardián")
    about_file(pv), pv.add_argument("--request", required=True), pv.add_argument("--secret", required=True), pv.add_argument("--out", required=True)
    gd = sub.add_parser("guardian", help="operaciones del guardián de un candado").add_subparsers(dest="op", required=True)
    for op in ("register", "release", "withdraw", "enroll", "revoke", "head", "adopt-anchor"):
        p = command(op, _guardian, parent=gd)
        p.add_argument("--lock"), p.add_argument("--share", action="append", default=[]), p.add_argument("--journal", required=True)
        p.add_argument("--anchor", help="archivo en OTRO medio que guarda la cabeza del diario"), p.add_argument("--pin")
        if op in ("register", "release", "withdraw"):
            about_file(p)
        if op == "release":
            p.add_argument("--request", required=True), p.add_argument("--proof", required=True), p.add_argument("--out", required=True)
        if op in ("enroll", "revoke"):
            p.add_argument("--requester", required=True)
        if op == "enroll":
            p.add_argument("--out", required=True)
    o = command("open", _open, help_text="abre con el quórum")
    o.add_argument("file"), o.add_argument("dst"), o.add_argument("--sender-pub", required=True), o.add_argument("--key", required=True)
    o.add_argument("parts", nargs="+"), o.add_argument("--token", action="append", default=[])
    return ap


def main(argv: list[str] | None = None) -> int:
    a = _parser().parse_args(argv)
    try:
        a.handler(a)
    except (QCEError, OSError, ValueError, KeyError, TypeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0
