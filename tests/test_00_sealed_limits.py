"""Lo que se quitó de la lista de límites del sobre sellado: rotación y revocación, varias anclas, latidos y caducidad según el diario, frases al azar y modo discreto."""
import base64
import itertools
import json
import os
from pathlib import Path

import pytest

from qce.core.errors import AuthenticationFailure, IntegrityError, MalformedMessage, PolicyViolation, QCEError
from qce.pqc.hybrid import HIGH, STANDARD, HybridSigPrivateKey
from qce.sealed import cli, journal, keys
from qce.sealed import envelope as qsello
from qce.sealed import keeper as guardian

from tests.test_00_sealed import DATA, NOW, Clock, World, _keeper, _proof, _request_at

PHRASE = "una frase de pruebas larga"


@pytest.fixture(scope="module")
def limits_world(tmp_path_factory):
    return World(tmp_path_factory.mktemp("w"))


@pytest.fixture
def w(limits_world, tmp_path):
    limits_world.tmp = tmp_path
    return limits_world


def _custodian(w, who="bea", clock=None, **kw):
    return guardian.Custodian(w.cust[who], w.tmp / f"{who}.diario", clock=clock or Clock(), **kw)


def _stranger():
    return HybridSigPrivateKey.generate().public_bytes


# ------------------------------------------------------------------------------------------------ caducidad según el diario y latidos
def _giver(w, kind, clock):
    """Quien entrega (guardián o custodio) con una solicitud válida de NOW a NOW+600, lista para atender."""
    if kind == "keeper":
        lock = qsello.Lock.generate("reloj")
        f = w.seal(DATA, locks=[lock])
        k = _keeper(w, lock, clock=clock)
        k.register(f, w.sender.public_bytes)
        request = _request_at(w, f, ttl=600)
        proof = _proof(w, k, f, request)
        return k, lambda: k.release(f, w.sender.public_bytes, request, proof)
    f = w.seal(DATA)
    c = _custodian(w, clock=clock)
    request = _request_at(w, f, ttl=600)
    return c, lambda: c.contribute(f, w.sender.public_bytes, request)


@pytest.mark.parametrize("kind", ["keeper", "custodian"])
@pytest.mark.parametrize("beat,ok", [(NOW + 600, True), (NOW + 601, False), (NOW + 700, False)])
def test_a_request_that_expired_before_the_last_journal_entry_is_dead_whatever_the_clock_says(w, kind, beat, ok):
    clock = Clock()
    giver, deliver = _giver(w, kind, clock)
    clock.t = beat
    giver.tick()
    clock.t = NOW + 500                                                       # el reloj retrocede MENOS que la holgura del diario: se podría anotar
    if ok:
        assert deliver()
    else:
        before = giver.journal.path.read_bytes()
        with pytest.raises(PolicyViolation, match="según el diario"):
            deliver()
        assert giver.journal.path.read_bytes() == before


@pytest.mark.parametrize("kind", ["keeper", "custodian"])
def test_control_without_a_later_entry_a_clock_set_back_still_revives_the_request(w, kind):
    """El límite que QUEDA: si nada se anotó después de la caducidad, el diario no sabe que pasó el tiempo."""
    clock = Clock(NOW + 100)
    _, deliver = _giver(w, kind, clock)
    assert deliver()


def test_a_heartbeat_changes_nothing_but_the_time(w):
    clock = Clock()
    k, deliver = _giver(w, "keeper", clock)
    k.tick()
    assert deliver() and len(k.deliveries()) == 1
    k.tick()
    with pytest.raises(PolicyViolation, match="YA se atendió"):
        deliver()
    assert [e["type"] for e in k.journal.read()] == ["enroll", "register", "tick", "deliver", "tick"]


def test_a_custodian_heartbeat_is_not_a_delivery(w):
    f = w.seal(DATA)
    c = _custodian(w)
    c.tick()
    request = _request_at(w, f)
    assert c.contribute(f, w.sender.public_bytes, request)
    c.tick()
    with pytest.raises(PolicyViolation, match="YA se atendió"):
        c.contribute(f, w.sender.public_bytes, request)
    assert len(c.served()) == 1 and len(c.journal.read()) == 3


# ------------------------------------------------------------------------------------------------ varias anclas (testigos)
def _two_anchors(w):
    lock, clock = qsello.Lock.generate("testigos"), Clock()
    path, a, b = w.tmp / "g.diario", w.tmp / "usb" / "a.ancla", w.tmp / "nube" / "b.ancla"
    make = lambda anchors=(a, b): guardian.Keeper(lock, path, clock=clock, anchor=list(anchors))  # noqa: E731
    make().enroll(w.requester.public_bytes)
    return make, path, a, b


def test_every_anchor_is_written_and_restoring_the_journal_with_only_some_of_them_is_detected(w):
    make, path, a, b = _two_anchors(w)
    old = path.read_bytes(), a.read_bytes(), b.read_bytes()
    make().enroll(_stranger())
    assert a.read_bytes() == b.read_bytes() and json.loads(a.read_text())["n"] == 2
    new_b = b.read_bytes()
    path.write_bytes(old[0]), a.write_bytes(old[1])                           # se restauran el diario y UNA ancla
    for anchors in ((a, b), (b,)):
        with pytest.raises(IntegrityError, match="anclada"):
            make(anchors).journal.head()
    assert make((a,)).journal.head()[0] == 1                                  # control: quien solo mira esa ancla no se entera
    b.write_bytes(old[2])
    assert make().journal.head()[0] == 1                                      # límite: restaurar TODO a la vez no se detecta
    b.write_bytes(new_b), a.write_bytes(new_b)
    with pytest.raises(IntegrityError, match="anclada"):
        make().journal.head()


def test_a_missing_anchor_among_several_stops_the_journal_until_adopted_and_adoption_does_not_forgive_the_rest(w):
    make, path, a, b = _two_anchors(w)
    old = path.read_bytes()
    make().enroll(_stranger())
    full = path.read_bytes()
    b.unlink()
    with pytest.raises(IntegrityError, match="falta el ancla"):
        make().enroll(_stranger())
    path.write_bytes(old)
    with pytest.raises(IntegrityError, match="anclada"):                      # adoptar la que falta sigue exigiendo las que existen
        make().journal.adopt_anchor()
    assert not b.exists()
    path.write_bytes(full)
    make().journal.adopt_anchor()
    assert a.read_bytes() == b.read_bytes() and make().journal.head()[0] == 2
    with pytest.raises(PolicyViolation, match="adoptar"):
        make().journal.adopt_anchor()


def test_adoption_creates_only_the_missing_anchor(w):
    make, path, a, b = _two_anchors(w)
    stale = a.read_bytes()
    make().enroll(_stranger())
    a.write_bytes(stale)                                                      # una ancla atrasada es válida (prefijo) y adoptar no la toca
    b.unlink()
    make().journal.adopt_anchor()
    assert a.read_bytes() == stale and json.loads(b.read_text())["n"] == 2


def test_if_the_second_anchor_cannot_be_written_nothing_is_handed_out(w, monkeypatch):
    make, path, a, b = _two_anchors(w)
    real = journal.atomic_write

    def fail_on_b(target, data, mode):
        if Path(target) == b:
            raise OSError("sin medio")
        real(target, data, mode)
    monkeypatch.setattr(journal, "atomic_write", fail_on_b)
    with pytest.raises(OSError):
        make().enroll(_stranger())
    monkeypatch.setattr(journal, "atomic_write", real)
    assert make().journal.head()[0] == 2 and json.loads(a.read_text())["n"] == 2 and json.loads(b.read_text())["n"] == 1


@pytest.mark.parametrize("anchors", [("x", "x"), ("d/../x", "x"), ("g.diario",)])
def test_each_anchor_must_be_a_different_file_from_the_others_and_from_the_journal(tmp_path, anchors):
    (tmp_path / "d").mkdir()
    with pytest.raises(PolicyViolation, match="distinto"):
        journal.Journal(tmp_path / "g.diario", bytes(32), {}, anchor=[tmp_path / a for a in anchors])


# ------------------------------------------------------------------------------------------------ frases al azar
def test_a_random_passphrase_carries_128_bits(tmp_path):
    phrases = {keys.random_passphrase() for _ in range(50)}
    assert len(phrases) == 50
    for p in phrases:
        groups = p.split("-")
        assert [len(g) for g in groups] == [5, 5, 5, 5, 5, 1]
        assert len(base64.b32decode("".join(groups) + "=" * 6)) == 16


def _fake_terminal(tmp_path, monkeypatch):
    tty = tmp_path / "terminal"
    tty.write_text("")
    monkeypatch.setattr(cli, "TERMINAL", str(tty))
    return tty


def test_the_command_line_can_generate_the_phrase_of_a_new_key(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    tty = _fake_terminal(tmp_path, monkeypatch)
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: pytest.fail("no debe preguntar"))
    assert cli.main(["keygen", "emisor", "ana", "--generate-passphrase"]) == 0
    phrase = tty.read_text().split("no se guarda en ningún sitio): ")[1].split("\n")[0]
    assert len(phrase) == 31 and keys.load_secret(tmp_path / "ana.key", keys.EMISOR, phrase)[1]
    said = capsys.readouterr()
    assert phrase not in said.out + said.err and "anótala" not in said.out + said.err      # nada de la frase por la salida
    (tmp_path / "f").write_text(PHRASE)
    (tmp_path / "f").chmod(0o600)
    assert cli.main(["keygen", "emisor", "eva", "--generate-passphrase", "--passphrase-file", "f"]) == 1
    assert "se excluyen" in capsys.readouterr().err and not (tmp_path / "eva.key").exists()


# ------------------------------------------------------------------------------------------------ modo discreto
def _hidden(w, data=DATA, name="discreto", **kw):
    return w.seal(data, name, hidden=True, **kw)


def _header(w, f):
    return qsello.read_header(f, w.sender.public_bytes)


C, F = qsello.CHUNK, qsello.PAD_FLOOR


@pytest.mark.parametrize("size", [0, 1, F - 8, F - 7, C - 8, C - 7, C, 2 * C - 8, 3 * C + 5])
def test_a_discreet_file_gives_back_exactly_the_plaintext(w, size):
    data = os.urandom(size)
    f = _hidden(w, data)
    out, rep = w.open(f, [w.part(f, n) for n in ("bea", "dani", "fer")])
    assert out == data and rep["rejected"] == []


@pytest.mark.parametrize("level", [STANDARD, HIGH])
def test_discreet_mode_works_at_both_levels(tmp_path, level):
    w = World(tmp_path, level)
    f = _hidden(w)
    assert _header(w, f).hidden and w.open(f, [w.part(f, n) for n in ("carla", "dani", "eva")])[0] == DATA


def test_a_discreet_header_names_nobody_and_two_files_share_no_identifier(w):
    lock = qsello.Lock.generate("herencia-familia")
    files = [_hidden(w, name=n, locks=[lock]) for n in ("uno", "dos")]
    heads = [_header(w, f) for f in files]
    secrets_of_the_policy = [qsello.fingerprint(k.public_bytes) for k in w.cust.values()] + [qsello.fingerprint(w.requester.public_bytes), lock.ident.hex(), lock.label,
                                                                                             "direccion", "legal"]
    for hd in heads:
        assert hd.data["v"] == 5 and not any(s.encode() in hd.raw for s in secrets_of_the_policy)
        assert [g["name"] for g in hd.data["groups"]] == ["g1", "g2"] and [k["label"] for k in hd.data["locks"]] == ["candado"]

    def identifiers(hd):
        d = hd.data
        return {m["id"] for g in d["groups"] for m in g["members"]} | set(d["openers"]) | {k["id"] for k in d["locks"]} | {d["saltcom"]}
    assert len(identifiers(heads[0])) == 5 + 1 + 1 + 1 and not identifiers(heads[0]) & identifiers(heads[1])
    salts = {qsello._unwrap(hd, w.cust["bea"])[3] for hd in heads}            # la sal que ciega a los solicitantes es nueva en cada archivo
    assert len(salts) == 2 and bytes(32) not in salts


def test_control_the_normal_header_does_name_them(w):
    hd = _header(w, w.seal(DATA))
    assert qsello.fingerprint(w.cust["bea"].public_bytes).encode() in hd.raw and b"direccion" in hd.raw


@pytest.mark.parametrize("n,expected", [(0, F), (F, F), (F + 1, 4352), (C, C), (C + 1, C + 2048), (10**9, 1_006_632_960)])
def test_the_padded_size_known_values(n, expected):
    assert qsello.padded_size(n) == expected


def test_padding_never_shrinks_never_costs_more_than_a_twelfth_and_never_goes_down():
    previous = 0
    for n in itertools.chain(range(F, F + 3000), (2**i + d for i in range(13, 40) for d in (-1, 0, 1, 12345))):
        p = qsello.padded_size(n)
        assert n <= p <= max(F, n + n // 8)
        if n < F + 3000:
            assert p >= previous
            previous = p


def test_the_body_length_of_a_discreet_file_only_reveals_the_bucket(w):
    lengths = {qsello.verify_file(_hidden(w, os.urandom(n), f"t{n}"), w.sender.public_bytes)[2] for n in (0, 1, 100, 2000, F - 8)}
    assert lengths == {F + qsello.TAG}
    assert qsello.verify_file(_hidden(w, os.urandom(F - 7), "mas"), w.sender.public_bytes)[2] == 4352 + qsello.TAG


def test_an_outsider_cannot_collect_shares_of_a_discreet_file_even_though_the_request_is_accepted_for_signing(w):
    f = _hidden(w)
    intruder = HybridSigPrivateKey.generate()
    request = qsello.request_open(f, w.sender.public_bytes, intruder, w.opener.public_bytes, "yo", now=NOW)   # no puede saber que no está en la lista…
    for give in (lambda: qsello.contribute(f, w.sender.public_bytes, w.cust["bea"], request, NOW), lambda: _custodian(w).contribute(f, w.sender.public_bytes, request)):
        with pytest.raises(PolicyViolation, match="NO autorizado"):           # …pero los custodios sí
            give()
    assert not (w.tmp / "bea.diario").exists() or not _custodian(w).served()


def test_the_list_of_requesters_cannot_be_checked_without_the_committed_salt(w):
    f = _hidden(w)
    hd = _header(w, f)
    request = w.request(f)
    gi, x, share, salt = qsello._unwrap(hd, w.cust["bea"])
    assert qsello.read_request(hd, request, salt=salt).requester == qsello.fingerprint(w.requester.public_bytes)
    for wrong in (b"", bytes(32), salt[:-1] + bytes([salt[-1] ^ 1])):
        with pytest.raises(AuthenticationFailure, match="sal"):
            qsello.read_request(hd, request, salt=wrong)
    assert qsello.inspect_request(hd, request).requester == qsello.fingerprint(w.requester.public_bytes)
    assert qsello._unwrap(hd, w.cust["eva"])[3] == salt                       # todos reciben la misma


def test_a_key_that_is_not_in_a_discreet_file_gets_nothing(w):
    f = _hidden(w, groups=[w.group("a", 1, "bea")])
    with pytest.raises(PolicyViolation, match="no es de ningún custodio"):
        w.part(f, "carla")


def _lock_world(w, hidden=True):
    lock, clock = qsello.Lock.generate("herencia"), Clock()
    f = w.seal(DATA, "con-candado", locks=[lock], hidden=hidden)
    k = _keeper(w, lock, clock=clock)
    k.register(f, w.sender.public_bytes)
    return lock, f, k


def test_a_discreet_file_with_a_lock_opens_through_the_keeper_even_from_a_stub(w):
    lock, f, k = _lock_world(w)
    stub = w.tmp / "r.stub"
    stub.write_bytes(qsello.make_stub(f, w.sender.public_bytes))
    request = _request_at(w, stub)
    token = k.release(stub, w.sender.public_bytes, request, _proof(w, k, stub, request))
    assert lock.ident.hex() not in token.decode()
    parts = [_custodian(w, n).contribute(stub, w.sender.public_bytes, request) for n in ("bea", "carla", "eva")]
    assert w.open(f, parts, tokens=[token])[0] == DATA
    with pytest.raises(PolicyViolation, match="falta la ficha"):
        w.open(f, parts, out="sin.bin")


def test_the_keeper_of_a_discreet_file_also_refuses_a_requester_the_sender_did_not_list(w):
    lock, f, k = _lock_world(w)
    other = HybridSigPrivateKey.generate()
    k.enroll(other.public_bytes)                                              # de alta en el guardián, pero NO en la cabecera
    request = qsello.request_open(f, w.sender.public_bytes, other, w.opener.public_bytes, "quiero", now=NOW)
    ident = qsello.inspect_request(_header(w, f), request, NOW).ident
    proof = guardian.prove(ident, k.requester_secret(qsello.fingerprint(other.public_bytes)))
    with pytest.raises(PolicyViolation, match="NO autorizado"):
        k.release(f, w.sender.public_bytes, request, proof)
    assert k.deliveries() == []


def test_a_lock_that_is_not_of_a_discreet_file_is_refused(w):
    _, f, _ = _lock_world(w)
    with pytest.raises(PolicyViolation, match="no es de este archivo"):
        _keeper(w, qsello.Lock.generate("ajeno"), name="otro").register(f, w.sender.public_bytes)


def _resigned(w, f, mutate):
    """El emisor (aquí, nosotros) firma una cabecera alterada de un archivo discreto, conservando el cuerpo."""
    hd = _header(w, f)
    obj = json.loads(hd.raw)
    mutate(obj)
    raw = json.dumps(obj).encode()
    prefix = qsello.MAGIC + len(raw).to_bytes(4, "big") + raw
    bad = w.tmp / "resignado.qsel"
    body = f.read_bytes()[hd.payload_start: -hd.level.sig_len]
    digest = __import__("hashlib").sha256(prefix).digest()
    bad.write_bytes(prefix + w.sender.sign(prefix, qsello.CTX_HEADER) + body
                    + w.sender.sign(digest + __import__("hashlib").sha256(body).digest() + len(body).to_bytes(8, "big"), qsello.CTX_FILE))
    return bad


def test_a_dealer_cannot_hand_out_a_salt_other_than_the_committed_one(w, monkeypatch):
    with monkeypatch.context() as m:
        m.setattr(qsello, "_salt_commitment", lambda sid, salt: "0" * 64)    # un emisor que compromete una sal y reparte otra
        bad = _hidden(w, name="incoherente")
    with pytest.raises(AuthenticationFailure, match="sal de los solicitantes"):
        w.part(bad, "bea")


def test_a_damaged_lock_salt_stops_the_keeper(w):
    lock, f, _ = _lock_world(w)
    bad = _resigned(w, f, lambda o: o["locks"][0].update(salt=qsello._b64(bytes(48))))
    k = _keeper(w, lock, name="dos")
    k.register(bad, w.sender.public_bytes)
    request = _request_at(w, bad)
    with pytest.raises(AuthenticationFailure, match="sal del candado"):
        k.release(bad, w.sender.public_bytes, request, _proof(w, k, bad, request))


_HIDDEN_MUTATIONS = {
    "sin compromiso de sal": lambda o: o.pop("saltcom"), "compromiso de sal mal formado": lambda o: o.update(saltcom="z"),
    "participación de modo normal": lambda o: o["groups"][0]["members"][0].update(box=qsello._b64(bytes(48))),
    "versión 4 con sal": lambda o: o.update(v=4), "versión 3 con sal": lambda o: o.update(v=3), "candado sin sal": lambda o: o["locks"][0].pop("salt"),
    "sal de candado corta": lambda o: o["locks"][0].update(salt=qsello._b64(bytes(32))), "versión 6": lambda o: o.update(v=6), "versión 5.0": lambda o: o.update(v=5.0),
}


@pytest.mark.parametrize("name", sorted(_HIDDEN_MUTATIONS))
def test_a_signed_discreet_header_must_also_be_strictly_well_formed(w, name):
    _, f, _ = _lock_world(w)
    with pytest.raises(MalformedMessage):
        _header(w, _resigned(w, f, _HIDDEN_MUTATIONS[name]))


def test_a_normal_header_cannot_carry_discreet_fields(w):
    bad = _resigned(w, w.seal(DATA), lambda o: o.update(saltcom="0" * 64))
    with pytest.raises(MalformedMessage):
        _header(w, bad)


class _Bytes:
    def __init__(self, data, size=None):
        self.data, self.size = data, len(data) if size is None else size

    def read(self, n):
        out, self.data = self.data[:n], self.data[n:]
        return out


@pytest.mark.parametrize("declared,why", [(50, "creció"), (150, "se acortó")])
def test_a_source_whose_size_changes_while_sealing_is_refused_and_nothing_is_written(w, declared, why):
    with pytest.raises(MalformedMessage, match=why):
        qsello.seal(_Bytes(os.urandom(100), declared), w.tmp / "x.qsel", w.sender, w.groups(), [w.requester.public_bytes], hidden=True)
    assert not (w.tmp / "x.qsel").exists() and not list(w.tmp.glob(".x.qsel-*"))


def _padded_chunks(length, data, pad):
    return [length.to_bytes(8, "big") + data, pad]


@pytest.mark.parametrize("chunks,why", [
    ([b"1234567"], "imposible"),
    (_padded_chunks(3, b"abc\x00\x01", b""), "no es de ceros"),
    (_padded_chunks(3, b"abc", b"\x00\x00\x07"), "no es de ceros"),
    (_padded_chunks(9, b"abc", b"de"), "más datos"),
])
def test_impossible_padding_is_refused(chunks, why):
    with pytest.raises(MalformedMessage, match=why):
        list(qsello._unpadded(iter(chunks)))


def test_the_padding_is_removed_across_chunk_boundaries():
    assert b"".join(qsello._unpadded(iter(_padded_chunks(5, b"abc", b"de\x00\x00")))) == b"abcde"


# ------------------------------------------------------------------------------------------------ rotación y revocación
def _reseal(w, f, who, dst, groups, tokens=None, **kw):
    request = w.request(f)
    parts = [qsello.contribute(f, w.sender.public_bytes, w.cust[n], request) for n in who]
    return qsello.reseal(f, dst, w.sender.public_bytes, w.opener, parts, w.sender, groups, [w.requester.public_bytes], lock_tokens=tokens, **kw)


@pytest.mark.parametrize("was,becomes", [(False, None), (False, True), (True, None), (True, False)])
@pytest.mark.parametrize("size", [0, 100, C, C + 1, 2 * C, 2 * C - 8])
def test_resealing_keeps_the_content_under_a_new_policy_and_key(w, was, becomes, size):
    data = os.urandom(size)
    f = w.seal(data, hidden=was)
    new = w.tmp / "nuevo.qsel"
    header, report = _reseal(w, f, ("bea", "carla", "eva"), new, [w.group("nuevo", 2, "bea", "fer")], hidden=becomes)
    assert header.hidden == (was if becomes is None else becomes) and report["rejected"] == []
    assert header.data["commit"] != _header(w, f).data["commit"] and header.data["sid"] != _header(w, f).data["sid"]
    assert w.open(new, [w.part(new, n) for n in ("bea", "fer")])[0] == data
    with pytest.raises(PolicyViolation, match="no es de ningún custodio"):
        w.part(new, "carla")


def test_resealing_never_writes_the_plaintext_to_disk(w):
    data = os.urandom(3 * C + 11)
    f = w.seal(data)
    (w.tmp / "doc.bin").unlink()                                              # el original en claro, fuera
    _reseal(w, f, ("bea", "carla", "eva"), w.tmp / "nuevo.qsel", w.groups())
    for p in w.tmp.rglob("*"):
        if p.is_file():
            blob = p.read_bytes()
            assert data[:64] not in blob and data[-64:] not in blob and data[C: C + 64] not in blob, p.name
    assert {p.name for p in w.tmp.iterdir()} == {"doc.qsel", "nuevo.qsel"}


def test_resealing_refuses_to_overwrite_the_original_and_publishes_nothing_without_a_quorum(w):
    f = w.seal(DATA)
    before = f.read_bytes()
    for target in (f, w.tmp / "." / "doc.qsel"):
        with pytest.raises(PolicyViolation, match="sobre el archivo original"):
            _reseal(w, f, ("bea", "carla", "eva"), target, w.groups())
    with pytest.raises(PolicyViolation, match="quórum insuficiente"):
        _reseal(w, f, ("bea", "eva"), w.tmp / "no.qsel", w.groups())
    assert f.read_bytes() == before and not (w.tmp / "no.qsel").exists()


@pytest.mark.parametrize("size,hidden", [(100, False), (C, False), (100, True)])
def test_a_body_swapped_during_a_reseal_publishes_nothing(w, monkeypatch, size, hidden):
    f = w.seal(os.urandom(size), hidden=hidden)
    request = w.request(f)
    parts = [qsello.contribute(f, w.sender.public_bytes, w.cust[n], request) for n in ("bea", "carla", "eva")]
    hd = _header(w, f)
    shares = {(gi, x): s for gi, x, s in (qsello._check_contribution(hd, p, w.opener) for p in parts)}
    cipher = qsello.AEADS[hd.data["aead"]](qsello._payload_key(qsello.recover_secret(hd, shares), hd.digest))
    real = qsello.verify_file

    def verify_then_swap(path, sender_public):
        result = real(path, sender_public)
        raw = bytearray(Path(path).read_bytes())
        end = len(raw) - hd.level.sig_len
        plain = bytearray(cipher.decrypt(bytes(11) + b"\x01", bytes(raw[hd.payload_start:end]), None))
        plain[-1 if not hidden else 8] ^= 1
        raw[hd.payload_start:end] = cipher.encrypt(bytes(11) + b"\x01", bytes(plain), None)
        Path(path).write_bytes(raw)
        return result
    monkeypatch.setattr(qsello, "verify_file", verify_then_swap)
    with pytest.raises(AuthenticationFailure, match="cambió mientras se abría"):
        qsello.reseal(f, w.tmp / "n.qsel", w.sender.public_bytes, w.opener, parts, w.sender, w.groups(), [w.requester.public_bytes])
    assert not (w.tmp / "n.qsel").exists() and not list(w.tmp.glob(".n.qsel-*"))


def test_after_rotating_a_locked_file_the_old_copy_gets_no_new_token(w):
    """Revocar a «dani»: volver a sellar sin esa persona, registrar el nuevo y RETIRAR el viejo en el guardián."""
    lock, f, k = _lock_world(w, hidden=False)
    request = _request_at(w, f)
    token = k.release(f, w.sender.public_bytes, request, _proof(w, k, f, request))
    new = w.tmp / "nuevo.qsel"
    _reseal(w, f, ("bea", "carla", "eva"), new, [w.group("direccion", 2, "bea", "carla")], tokens=[token], locks=[lock])
    k.register(new, w.sender.public_bytes)
    k.withdraw(_header(w, f).digest.hex(), _header(w, f).data["sid"])
    again = _request_at(w, f, reason="otra vez")
    with pytest.raises(PolicyViolation, match="retirado"):
        k.release(f, w.sender.public_bytes, again, _proof(w, k, f, again))
    parts = [w.part(f, n) for n in ("dani", "bea", "eva")]
    with pytest.raises(PolicyViolation, match="falta la ficha"):
        w.open(f, parts, out="viejo.bin")
    assert w.open(f, parts, out="con-ficha-vieja.bin", tokens=[token])[0] == DATA       # límite: una ficha ya entregada sigue valiendo


def test_custodians_who_withdraw_a_file_leave_the_revoked_one_without_a_quorum(w):
    f = w.seal(DATA, groups=[w.group("direccion", 2, "bea", "carla", "dani")])
    name = _header(w, f).data["sid"]
    for n in ("bea", "carla"):
        _custodian(w, n).withdraw(name)
        with pytest.raises(PolicyViolation, match="RETIRÓ"):                   # persiste: es el diario quien lo recuerda
            _custodian(w, n).contribute(f, w.sender.public_bytes, _request_at(w, f))
        with pytest.raises(PolicyViolation, match="ya estaba retirado"):
            _custodian(w, n).withdraw(name)
    request = _request_at(w, f)
    only = _custodian(w, "dani").contribute(f, w.sender.public_bytes, request)
    with pytest.raises(PolicyViolation, match="quórum insuficiente"):
        w.open(f, [only])
    other = w.seal(DATA, "otro", groups=[w.group("direccion", 1, "bea")])
    assert _custodian(w, "bea").contribute(other, w.sender.public_bytes, _request_at(w, other))


def test_control_without_withdrawals_the_old_copy_still_opens(w):
    f = w.seal(DATA, groups=[w.group("direccion", 2, "bea", "carla", "dani")])
    _custodian(w, "bea").withdraw(_header(w, f).data["sid"])
    parts = [_custodian(w, n).contribute(f, w.sender.public_bytes, _request_at(w, f)) for n in ("carla", "dani")]
    assert w.open(f, parts)[0] == DATA


@pytest.mark.parametrize("bad", ["", "ab", "A" * 64, "g" * 64, "0" * 63, "0" * 65])
def test_a_withdrawal_needs_a_real_file_identifier(w, bad):
    with pytest.raises(PolicyViolation, match="inválido"):
        _custodian(w).withdraw(bad)
    assert not (w.tmp / "bea.diario").exists()


# ------------------------------------------------------------------------------------------------ línea de comandos
def test_rotation_and_custodian_memory_from_the_command_line(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "frase").write_text(PHRASE)
    (tmp_path / "frase").chmod(0o600)

    def run(*argv, ok=True):
        code = cli.main([*argv, "--passphrase-file", "frase"])
        assert (code == 0) == ok, (argv, capsys.readouterr())
        return capsys.readouterr()
    for kind, name in (("emisor", "ana"), ("emisor", "gil"), ("custodio", "bea"), ("custodio", "carla"), ("custodio", "apertura"), ("candado", "plazo")):
        run("keygen", kind, name)
    (tmp_path / "doc.txt").write_text("acta")
    sp, lk = ["--sender-pub", "ana.pub"], ["--lock", "plazo.candado", "--journal", "g.diario", "--anchor", "g1.ancla", "--anchor", "g2.ancla"]
    seal = run("seal", "doc.txt", "d.qsel", "--sender", "ana.key", "--opener", "gil.pub", "--group", "dir:1:bea.pub,carla.pub", "--lock", "plazo.candado", "--discreet")
    assert '"discreet": true' in seal.out
    run("guardian", "register", "d.qsel", *sp, *lk)
    run("guardian", "enroll", *lk, "--requester", "gil.pub", "--out", "gil.secreto")
    run("guardian", "tick", *lk)
    assert (tmp_path / "g1.ancla").read_bytes() == (tmp_path / "g2.ancla").read_bytes()
    run("request", "d.qsel", *sp, "--key", "gil.key", "--to", "apertura.pub", "--reason", "rotar", "--out", "s.req")
    mem = ["--key", "bea.key", "--anchor", "bea1.ancla", "--anchor", "bea2.ancla"]
    assert "aún sin comprobar" in run("contribute", "d.qsel", *sp, *mem, "--request", "s.req", "--out", "bea.part").out
    run("prove", "d.qsel", *sp, "--request", "s.req", "--secret", "gil.secreto", "--out", "s.prueba")
    run("guardian", "release", "d.qsel", *sp, *lk, "--request", "s.req", "--proof", "s.prueba", "--out", "d.ficha")
    rotate = ["reseal", "d.qsel", "n.qsel", "bea.part", *sp, "--key", "apertura.key", "--token", "d.ficha", "--new-sender", "ana.key", "--opener", "gil.pub",
              "--group", "dir:1:carla.pub", "--lock", "plazo.candado"]
    assert "copias antiguas" in run(*rotate).out
    assert '"discreet": true' in run("info", "n.qsel", *sp).out
    run("seal", "doc.txt", "claro.qsel", "--sender", "ana.key", "--opener", "gil.pub", "--group", "dir:1:bea.pub")
    run("request", "claro.qsel", *sp, "--key", "gil.key", "--to", "apertura.pub", "--reason", "ocultar", "--out", "c.req")
    assert "solicitante autorizado" in run("contribute", "claro.qsel", *sp, *mem, "--request", "c.req", "--out", "c.part").out
    run("reseal", "claro.qsel", "oculto.qsel", "c.part", *sp, "--key", "apertura.key", "--new-sender", "ana.key", "--opener", "gil.pub", "--group", "dir:1:bea.pub",
        "--discreet")
    assert '"discreet": true' in run("info", "oculto.qsel", *sp).out
    run("custodian", "withdraw", "d.qsel", *sp, *mem)
    run("custodian", "tick", *mem)
    assert run("custodian", "head", *mem).out.startswith("4:")
    run("request", "d.qsel", *sp, "--key", "gil.key", "--to", "apertura.pub", "--reason", "despues", "--out", "t.req")
    assert "RETIRÓ" in run("contribute", "d.qsel", *sp, *mem, "--request", "t.req", "--out", "no.part", ok=False).err
    (tmp_path / "bea2.ancla").unlink()
    assert "falta el ancla" in run("custodian", "head", *mem, ok=False).err
    run("custodian", "adopt-anchor", *mem)
    run("custodian", "head", *mem)


# ------------------------------------------------------------------------------------------------ participaciones atadas a la política
def _transplant(w, f, mutate):
    """Atacante que puede FIRMAR como el emisor (p. ej. rompiendo sus firmas): copia las participaciones envueltas a una cabecera cambiada y pide que se las den."""
    intruder = HybridSigPrivateKey.generate()
    bad = _resigned(w, f, lambda o: mutate(o, qsello.fingerprint(intruder.public_bytes)))
    request = qsello.request_open(bad, w.sender.public_bytes, intruder, w.opener.public_bytes, "dadme", now=NOW) if mutate is _as_requester else _request_at(w, bad)
    return lambda: qsello.contribute(bad, w.sender.public_bytes, w.cust["bea"], request, NOW)


def _as_requester(o, intruder):
    o.update(openers=[intruder])


_POLICY_CHANGES = {
    "otro solicitante": _as_requester,
    "un solicitante más": lambda o, i: o["openers"].append(i),
    "sin candado": lambda o, i: o.update(locks=[]),
    "umbral rebajado": lambda o, i: o["groups"][0].update(k=1),
    "menos grupos necesarios": lambda o, i: o.update(need=1),
    "otro cifrado del cuerpo": lambda o, i: o.update(aead="CHACHA20-POLY1305"),
    "grupo renombrado": lambda o, i: o["groups"][1].update(name="otro"),
    "otro compromiso de clave": lambda o, i: o.update(commit="0" * 64),
}


@pytest.mark.parametrize("change", sorted(_POLICY_CHANGES))
def test_wrapped_shares_cannot_be_moved_to_a_header_with_another_policy(w, change):
    f = w.seal(DATA, locks=[qsello.Lock.generate("atado")])
    assert _transplant(w, f, lambda o, i: None)()                            # control: la misma cabecera firmada de nuevo sí vale
    with pytest.raises(AuthenticationFailure, match="no pertenece a esta política"):
        _transplant(w, f, _POLICY_CHANGES[change])()


def test_control_the_old_format_did_let_a_forger_collect_the_shares():
    """El ataque contra el formato 3 (vector publicado, cuya clave de emisor sale de una etiqueta): por eso ya no se escribe."""
    from tests.sealed_vector_cases import CASES, derive
    name = CASES[0]["name"]
    sender = HybridSigPrivateKey.from_seed(derive(name, "emisor", 64), STANDARD)
    custodian = qsello.XWING.from_seed(derive(name, "custodio-1-1", 32))
    f = Path(__file__).parent / "sealed_vectors" / f"{name}.qsel"
    hd = qsello.read_header(f, sender.public_bytes)
    intruder, intruder_kem = HybridSigPrivateKey.generate(), qsello.XWING.generate()
    obj = json.loads(hd.raw)
    obj["openers"] = [qsello.fingerprint(intruder.public_bytes)]
    raw = json.dumps(obj).encode()
    prefix = qsello.MAGIC + len(raw).to_bytes(4, "big") + raw
    body = f.read_bytes()[hd.payload_start: -hd.level.sig_len]
    import hashlib
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        bad = Path(d) / "trasplante.qsel"
        bad.write_bytes(prefix + sender.sign(prefix, qsello.CTX_HEADER) + body
                        + sender.sign(hashlib.sha256(prefix).digest() + hashlib.sha256(body).digest() + len(body).to_bytes(8, "big"), qsello.CTX_FILE))
        request = qsello.request_open(bad, sender.public_bytes, intruder, intruder_kem.public_bytes, "robo", now=NOW)
        part = qsello.contribute(bad, sender.public_bytes, custodian, request, NOW)
        gi, x, share = qsello._check_contribution(qsello.read_header(bad, sender.public_bytes), part, intruder_kem)
    assert qsello._h(b"QSEL3/share", bytes.fromhex(hd.data["sid"]), qsello._int(gi), qsello._int(x), share).hex() == hd.data["groups"][0]["members"][0]["com"]


def test_new_files_use_the_bound_format(w):
    assert [_header(w, w.seal(DATA, n, hidden=h)).data["v"] for n, h in (("a", False), ("b", True))] == [4, 5]


@pytest.mark.parametrize("hidden", [False, True])
def test_a_broken_ciphertext_in_one_slot_only_hurts_its_owner(w, hidden):
    """Un punto X25519 de orden bajo hace fallar la desencapsulación: el afectado recibe un error claro y los demás siguen encontrando su hueco."""
    f = w.seal(DATA, groups=[w.group("a", 1, "bea", "carla")], hidden=hidden)
    zero = qsello._b64(bytes(qsello.XWING.ct_len))
    bad = _resigned(w, f, lambda o: o["groups"][0]["members"][0].update(ct=zero))
    assert w.part(bad, "carla")
    with pytest.raises(QCEError, match="no es de ningún custodio" if hidden else "texto cifrado"):
        w.part(bad, "bea")


# ------------------------------------------------------------------------------------------------ hallazgos de la revisión
def _reserialised(w, f):
    """La MISMA cabecera escrita con otros bytes y firmada de nuevo: otra huella, las mismas participaciones."""
    again = _resigned(w, f, lambda o: None)
    assert _header(w, again).digest != _header(w, f).digest and _header(w, again).data == _header(w, f).data
    return again


def test_a_custodian_withdrawal_survives_a_header_rewritten_with_other_bytes(w):
    f = w.seal(DATA, groups=[w.group("a", 1, "bea")])
    copy = _reserialised(w, f)
    assert w.part(copy, "bea")                                                # control: sin retirada, la copia reescrita funciona
    c = _custodian(w)
    c.withdraw(_header(w, f).data["sid"])
    for target in (f, copy):
        with pytest.raises(PolicyViolation, match="RETIRÓ"):
            c.contribute(target, w.sender.public_bytes, _request_at(w, target))


def test_the_keeper_does_not_take_back_a_withdrawn_file_under_another_header(w):
    lock, f, k = _lock_world(w, hidden=False)
    copy = _reserialised(w, f)
    hd = _header(w, f)
    k.withdraw(hd.digest.hex(), hd.data["sid"])
    with pytest.raises(PolicyViolation, match="RETIRADO"):
        k.register(copy, w.sender.public_bytes)
    other = w.seal(DATA, "otro-con-candado", locks=[lock])
    assert k.register(other, w.sender.public_bytes)


def test_a_copy_registered_before_the_withdrawal_gets_no_token_either(w):
    lock, f, k = _lock_world(w, hidden=False)
    copy = _reserialised(w, f)
    k.register(copy, w.sender.public_bytes)
    hd = _header(w, f)
    k.withdraw(hd.digest.hex(), hd.data["sid"])
    request = _request_at(w, copy)
    with pytest.raises(PolicyViolation, match="retirado"):
        k.release(copy, w.sender.public_bytes, request, _proof(w, k, copy, request))
    assert k.deliveries() == []


@pytest.mark.parametrize("bad", ["", "A" * 64, "0" * 63])
def test_the_keeper_withdrawal_needs_a_real_file_identifier(w, bad):
    lock, f, k = _lock_world(w, hidden=False)
    before = k.journal.path.read_bytes()
    with pytest.raises(PolicyViolation, match="inválido"):
        k.withdraw(_header(w, f).digest.hex(), bad)
    assert k.journal.path.read_bytes() == before


@pytest.mark.parametrize("keep,ok", [(0, False), (1, False), (2, True)])
def test_resealing_never_drops_a_lock_unless_asked(w, keep, ok):
    locks = [qsello.Lock.generate("uno"), qsello.Lock.generate("dos")]
    f = w.seal(DATA, locks=locks, aead="CHACHA20-POLY1305")
    tokens = []
    for n, lock in enumerate(locks):
        k = _keeper(w, lock, name=f"k{n}", clock=Clock())
        k.register(f, w.sender.public_bytes)
        request = _request_at(w, f)
        tokens.append(k.release(f, w.sender.public_bytes, request, _proof(w, k, f, request)))
    new = w.tmp / "nuevo.qsel"

    def rotate(**kw):
        return _reseal(w, f, ("bea", "carla", "eva"), new, w.groups(), tokens=tokens, locks=locks[:keep], **kw)
    if not ok:
        with pytest.raises(PolicyViolation, match="MENOS candados"):
            rotate()
        assert not new.exists()
        assert len(rotate(drop_locks=True)[0].data["locks"]) == keep
    else:
        header, _ = rotate()
        assert len(header.data["locks"]) == 2 and header.data["aead"] == "CHACHA20-POLY1305"      # el cifrado se hereda
        assert rotate(aead="AES-256-GCM")[0].data["aead"] == "AES-256-GCM"


def test_the_command_line_drops_a_lock_only_with_the_explicit_option(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "frase").write_text(PHRASE)
    (tmp_path / "frase").chmod(0o600)

    def run(*argv, ok=True):
        code = cli.main([*argv, "--passphrase-file", "frase"])
        assert (code == 0) == ok, (argv, capsys.readouterr())
        return capsys.readouterr()
    for kind, name in (("emisor", "ana"), ("emisor", "gil"), ("custodio", "bea"), ("custodio", "apertura"), ("candado", "plazo")):
        run("keygen", kind, name)
    (tmp_path / "doc.txt").write_text("acta")
    sp, lk = ["--sender-pub", "ana.pub"], ["--lock", "plazo.candado", "--journal", "g.diario"]
    run("seal", "doc.txt", "d.qsel", "--sender", "ana.key", "--opener", "gil.pub", "--group", "dir:1:bea.pub", "--lock", "plazo.candado")
    run("guardian", "register", "d.qsel", *sp, *lk)
    run("guardian", "enroll", *lk, "--requester", "gil.pub", "--out", "gil.secreto")
    run("request", "d.qsel", *sp, "--key", "gil.key", "--to", "apertura.pub", "--reason", "quitar", "--out", "s.req")
    run("contribute", "d.qsel", *sp, "--key", "bea.key", "--request", "s.req", "--out", "bea.part")
    run("prove", "d.qsel", *sp, "--request", "s.req", "--secret", "gil.secreto", "--out", "s.prueba")
    run("guardian", "release", "d.qsel", *sp, *lk, "--request", "s.req", "--proof", "s.prueba", "--out", "d.ficha")
    rotate = ["reseal", "d.qsel", "n.qsel", "bea.part", *sp, "--key", "apertura.key", "--token", "d.ficha", "--new-sender", "ana.key", "--opener", "gil.pub",
              "--group", "dir:1:bea.pub"]
    assert "MENOS candados" in run(*rotate, ok=False).err and not (tmp_path / "n.qsel").exists()
    run(*rotate, "--drop-locks")
    assert '"locks": []' in run("info", "n.qsel", *sp).out


@pytest.mark.parametrize("argv", [["keygen", "candado", "caja"], ["keygen", "emisor", "ana"]])
def test_no_phrase_is_shown_for_a_key_that_already_exists(tmp_path, monkeypatch, capsys, argv):
    monkeypatch.chdir(tmp_path)
    tty = _fake_terminal(tmp_path, monkeypatch)
    assert cli.main([*argv, "--generate-passphrase"]) == 0 and "anótala" in tty.read_text()
    tty.write_text("")
    capsys.readouterr()
    assert cli.main([*argv, "--generate-passphrase"]) == 1
    assert "ya existe" in capsys.readouterr().err and tty.read_text() == ""


def test_without_a_terminal_no_phrase_is_generated_anywhere(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli, "TERMINAL", str(tmp_path / "no-existe" / "terminal"))
    assert cli.main(["keygen", "candado", "caja", "--generate-passphrase"]) == 1
    said = capsys.readouterr()
    assert "no hay terminal" in said.err and said.out == "" and not (tmp_path / "caja.candado").exists()


def _run_keygen(tmp_path, tty_fd=None, drain=None):
    """La orden en un proceso en sesión NUEVA (sin terminal heredada); con `tty_fd`, esa pseudoterminal pasa a ser la suya. La salida va a archivos. `drain` se
    llama mientras el proceso vive: en macOS cerrar una terminal con texto sin leer BLOQUEA, así que hay que ir leyéndolo."""
    import subprocess
    import sys
    import time
    adopt = "" if tty_fd is None else f"import fcntl, termios; fcntl.ioctl({tty_fd}, termios.TIOCSCTTY, 0); "
    code = f"import sys; {adopt}from qce.sealed import cli; sys.exit(cli.main(['keygen', 'candado', 'caja', '--generate-passphrase']))"
    root = Path(__file__).resolve().parents[1]
    out, err = tmp_path / "salida.txt", tmp_path / "errores.txt"
    with open(out, "w") as o, open(err, "w") as e:
        child = subprocess.Popen([sys.executable, "-c", code], stdout=o, stderr=e, cwd=tmp_path, env={**os.environ, "PYTHONPATH": str(root)},
                                 start_new_session=True, stdin=subprocess.DEVNULL, pass_fds=() if tty_fd is None else (tty_fd,))
        deadline = time.monotonic() + 60
        while child.poll() is None and time.monotonic() < deadline:
            if drain:
                drain()
            time.sleep(0.05)
        if child.poll() is None:
            child.kill()
            if drain:
                drain()
        child.wait(timeout=30)
    if drain:
        drain()
    return child.returncode, out.read_text() + err.read_text()


def test_a_process_with_redirected_output_shows_the_phrase_only_on_its_real_terminal(tmp_path):
    import select
    assert cli.TERMINAL == "/dev/tty"
    main_end, tty_end = os.openpty()
    shown = bytearray()

    def drain():
        while select.select([main_end], [], [], 0)[0]:
            try:
                data = os.read(main_end, 4096)
            except OSError:                                                    # Linux avisa así de que la terminal colgó…
                return
            if not data:                                                       # …y macOS, con un fin de archivo que se repite
                return
            shown.extend(data)
    try:
        status, output = _run_keygen(tmp_path, tty_end, drain)
    finally:
        os.close(main_end), os.close(tty_end)
    assert status == 0, output
    phrase = shown.decode().split("no se guarda en ningún sitio): ")[1].strip()
    assert keys.load_secret(tmp_path / "caja.candado", "candado", phrase)[1] and phrase not in output and "anótala" not in output


def test_a_process_with_no_terminal_refuses_to_generate_a_phrase(tmp_path):
    status, output = _run_keygen(tmp_path)
    assert status == 1 and "no hay terminal" in output and "anótala" not in output and not (tmp_path / "caja.candado").exists()


def test_two_anchors_that_differ_only_in_capitals_are_one_anchor(tmp_path):
    with pytest.raises(PolicyViolation, match="distinto"):
        journal.Journal(tmp_path / "g.diario", bytes(32), {}, anchor=[tmp_path / "Ancla", tmp_path / "ancla"])


def test_a_withdrawal_written_without_a_sid_by_the_previous_version_still_holds(w):
    lock, f, k = _lock_world(w, hidden=False)
    with k.journal.transaction() as (_, append):                              # así retiraba la versión anterior: sin anotar el `sid`
        append("withdraw", {"file": _header(w, f).digest.hex()})
    with pytest.raises(PolicyViolation, match="fue RETIRADO: no se vuelve a registrar"):
        k.register(f, w.sender.public_bytes)
    request = _request_at(w, f)
    with pytest.raises(PolicyViolation, match="retirado"):
        k.release(f, w.sender.public_bytes, request, _proof(w, k, f, request))
