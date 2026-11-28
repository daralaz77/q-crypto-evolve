"""Sobre sellado: claves cifradas, maestra repartida, ancla y reloj del diario, custodio con memoria, resguardos, quórum robusto y línea de comandos."""
import itertools
import json
import os
import stat

import pytest

from qce.core.errors import AuthenticationFailure, IntegrityError, MalformedMessage, PolicyViolation, QCEError
from qce.pqc.hybrid import HIGH, STANDARD, HybridSigPrivateKey
from qce.sealed import cli, journal, keys, lockshare, shamir
from qce.sealed import envelope as qsello
from qce.sealed import keeper as guardian

from tests.test_00_sealed import DATA, NOW, Clock, World, _keeper, _proof, _request_at, _setup, corrupting_split

PHRASE = "una frase de pruebas larga"


@pytest.fixture(scope="module")
def keys_world(tmp_path_factory):
    return World(tmp_path_factory.mktemp("w"))


@pytest.fixture
def w(keys_world, tmp_path):
    keys_world.tmp = tmp_path
    return keys_world


# ------------------------------------------------------------------------------------------------ claves cifradas
def _save(path, **kw):
    value = os.urandom(32)
    keys.save_secret(path, "candado", value, PHRASE, extra={"id": "ab" * 16, "label": "caja"}, n=2**14, **kw)
    return value


def test_a_stored_secret_comes_back_only_with_the_phrase_and_is_never_in_the_file(tmp_path):
    p = tmp_path / "c.candado"
    value = _save(p)
    raw = p.read_bytes()
    assert value not in raw and value.hex().encode() not in raw and qsello._b64(value).encode() not in raw
    assert stat.S_IMODE(p.stat().st_mode) == 0o600
    meta, got = keys.load_secret(p, "candado", PHRASE)
    assert got == value and meta["extra"]["label"] == "caja"
    with pytest.raises(AuthenticationFailure, match="frase incorrecta"):
        keys.load_secret(p, "candado", PHRASE + "x")


@pytest.mark.parametrize("field,value", [("level", "high"), ("algorithm", "otro"), ("extra", {"id": "cd" * 16, "label": "caja"}), ("n", 2**15),
                                         ("salt", qsello._b64(bytes(16))), ("nonce", qsello._b64(bytes(12))), ("box", qsello._b64(bytes(48)))])
def test_changing_any_field_of_a_key_file_stops_it_from_opening(tmp_path, field, value):
    p = tmp_path / "c.candado"
    _save(p)
    d = json.loads(p.read_text())
    d[field] = value
    p.write_text(json.dumps(d))
    with pytest.raises(AuthenticationFailure):
        keys.load_secret(p, "candado", PHRASE)


@pytest.mark.parametrize("field,value", [("n", 2**13), ("n", 2**18), ("n", 2**14 + 1), ("n", True), ("v", 2), ("v", True), ("extra", []), ("box", 5), ("box", "!!!!")])
def test_a_key_file_with_impossible_parameters_is_refused_before_deriving_anything(tmp_path, field, value):
    p = tmp_path / "c.candado"
    _save(p)
    d = json.loads(p.read_text())
    d[field] = value
    p.write_text(json.dumps(d))
    with pytest.raises(MalformedMessage):
        keys.load_secret(p, "candado", PHRASE)


def test_key_files_refuse_weak_phrases_other_kinds_and_overwriting(tmp_path):
    for phrase in ("", "corta", "x" * 11):
        with pytest.raises(PolicyViolation, match="al menos 12"):
            keys.save_secret(tmp_path / "a", "candado", bytes(32), phrase)
    with pytest.raises(PolicyViolation, match="tipo de secreto"):
        keys.save_secret(tmp_path / "a", "otro", bytes(32), PHRASE)
    p = tmp_path / "c.candado"
    value = _save(p)
    with pytest.raises(PolicyViolation, match="ya existe"):
        _save(p)
    assert keys.load_secret(p, "candado", PHRASE)[1] == value
    with pytest.raises(PolicyViolation, match="otro tipo"):
        keys.load_secret(p, "parte", PHRASE)
    keys.save_secret(tmp_path / "ok", "candado", bytes(32), "x" * 12, n=2**14)


def test_the_default_derivation_cost_is_the_vault_one(tmp_path):
    keys.save_secret(tmp_path / "d", "secreto", bytes(32), PHRASE)
    assert json.loads((tmp_path / "d").read_text())["n"] == 2**15


def test_a_public_key_file_declares_its_algorithm(tmp_path):
    key = HybridSigPrivateKey.generate()
    p = tmp_path / "a.pub"
    keys.save_public(p, keys.EMISOR, "standard", key.public_bytes)
    assert keys.load_public(p, keys.EMISOR) == key.public_bytes
    with pytest.raises(PolicyViolation):
        keys.save_public(p, keys.EMISOR, "standard", key.public_bytes)
    with pytest.raises(PolicyViolation, match="se esperaba"):
        keys.load_public(p, keys.CUSTODIO)
    good = json.loads(p.read_text())
    for bad in (dict(good, algorithm="x"), dict(good, level="otro"), dict(good, kind="custodio")):
        p.write_text(json.dumps(bad))
        with pytest.raises(PolicyViolation):
            keys.load_public(p, keys.EMISOR)
    for bad in (dict(good, public="zz"), dict(good, public=5), {"kind": "emisor"}):
        p.write_text(json.dumps(bad))
        with pytest.raises(MalformedMessage):
            keys.load_public(p, keys.EMISOR)


# ------------------------------------------------------------------------------------------------ maestra repartida
@pytest.mark.parametrize("k,n", [(2, 2), (2, 3), (3, 5)])
def test_every_set_of_k_parts_rebuilds_the_master_and_fewer_never_does(k, n):
    lock = qsello.Lock.generate("repartido")
    parts = lockshare.split_lock(lock, k, n)
    for subset in itertools.combinations(parts, k):
        assert lockshare.join_lock(list(subset)) == lock
    for subset in itertools.combinations(parts, k - 1):
        with pytest.raises(PolicyViolation, match="faltan partes|no hay partes"):
            lockshare.join_lock(list(subset))
    assert lockshare.join_lock(parts) == lock
    assert all(lock.key not in p.share for p in parts) and all(p.share.hex() not in repr(p) for p in parts)


@pytest.mark.parametrize("k,n", [(1, 3), (4, 3), (0, 2), (2, 17)])
def test_impossible_splits_are_refused(k, n):
    with pytest.raises(PolicyViolation, match="reparto inválido"):
        lockshare.split_lock(qsello.Lock.generate("x"), k, n)


def test_a_false_or_foreign_part_is_named_and_duplicates_do_not_count():
    lock = qsello.Lock.generate("x")
    a, b, c = lockshare.split_lock(lock, 2, 3)
    forged = lockshare.LockShare(b.ident, b.label, b.k, b.x, os.urandom(32), b.commitments, b.master)
    with pytest.raises(AuthenticationFailure, match="parte 2"):
        lockshare.join_lock([a, forged])
    with pytest.raises(AuthenticationFailure, match="parte 9"):
        lockshare.join_lock([a, lockshare.LockShare(b.ident, b.label, b.k, 9, b.share, b.commitments, b.master)])
    with pytest.raises(PolicyViolation, match="faltan partes"):
        lockshare.join_lock([a, a])
    other = lockshare.split_lock(lock, 2, 3)[1]                              # otro reparto de la MISMA maestra: no se mezclan
    with pytest.raises(PolicyViolation, match="distintos"):
        lockshare.join_lock([a, other])


def test_a_dishonest_split_that_does_not_rebuild_the_committed_master_is_caught():
    lock = qsello.Lock.generate("x")
    wrong = shamir.split(os.urandom(32), 2, 2)                                # partes coherentes consigo mismas, de OTRA clave
    commitments = tuple(lockshare._share_commitment(lock.ident, x, wrong[x]) for x in (1, 2))
    master = qsello._h(b"QSEL3/lock-master", lock.ident, lock.key).hex()
    parts = [lockshare.LockShare(lock.ident, lock.label, 2, x, wrong[x], commitments, master) for x in (1, 2)]
    with pytest.raises(AuthenticationFailure, match="inconsistente"):
        lockshare.join_lock(parts)


def test_a_keeper_assembled_from_parts_serves_files_sealed_with_the_whole_lock(w):
    lock = qsello.Lock.generate("junta")
    f = w.seal(DATA, locks=[lock])
    parts = lockshare.split_lock(lock, 2, 3)
    k = _keeper(w, lockshare.join_lock([parts[2], parts[0]]))
    k.register(f, w.sender.public_bytes)
    request = w.request(f)
    token = k.release(f, w.sender.public_bytes, request, _proof(w, k, f, request))
    assert w.open(f, [w.part(f, n) for n in ("bea", "carla", "eva")], tokens=[token])[0] == DATA


# ------------------------------------------------------------------------------------------------ ancla y reloj del diario
def _anchored(w, clock=None):
    clock = clock or Clock()
    lock = qsello.Lock.generate("anclado")
    path, anchor = w.tmp / "g.diario", w.tmp / "usb" / "g.ancla"
    k = guardian.Keeper(lock, path, clock=clock, anchor=anchor)
    k.enroll(w.requester.public_bytes)
    k.enroll(HybridSigPrivateKey.generate().public_bytes)
    return lock, k, clock, path, anchor


def test_an_anchor_detects_a_cut_or_restored_journal_without_anyone_remembering_a_code(w):
    lock, k, clock, path, anchor = _anchored(w)
    assert stat.S_IMODE(anchor.stat().st_mode) == 0o600 and json.loads(anchor.read_text())["n"] == 2
    full = path.read_bytes()
    path.write_bytes(full.splitlines(keepends=True)[0])                      # se corta el final
    with pytest.raises(IntegrityError, match="anclada"):
        k.journal.head()
    with pytest.raises(IntegrityError, match="anclada"):
        k.enroll(HybridSigPrivateKey.generate().public_bytes)
    path.unlink()                                                            # o se borra entero
    with pytest.raises(IntegrityError, match="anclada"):
        k.journal.head()
    path.write_bytes(full)
    assert k.journal.head()[0] == 2


def test_a_missing_damaged_or_forged_anchor_stops_the_journal(w):
    lock, k, clock, path, anchor = _anchored(w)
    good = anchor.read_bytes()
    anchor.unlink()
    with pytest.raises(IntegrityError, match="falta el ancla"):
        k.journal.head()
    for bad in (b"{", b"[]", b'{"n":0,"mac":"00","tag":"00"}', b'{"n":true,"mac":"00","tag":"00"}', b'{"n":1}', b"\xff"):
        anchor.write_bytes(bad)
        with pytest.raises(IntegrityError, match="dañada"):
            k.journal.head()
    d = json.loads(good)
    for forged in (dict(d, n=1), dict(d, mac="00" * 32), dict(d, tag="00" * 32)):
        anchor.write_text(json.dumps(forged))
        with pytest.raises(IntegrityError, match="no está autenticada"):
            k.journal.head()
    anchor.write_bytes(good)
    assert k.journal.head()[0] == 2


def test_adopting_an_anchor_is_an_explicit_act_and_only_once(w):
    lock = qsello.Lock.generate("tarde")
    plain = guardian.Keeper(lock, w.tmp / "g.diario", clock=Clock())
    plain.enroll(w.requester.public_bytes)
    late = guardian.Keeper(lock, w.tmp / "g.diario", clock=Clock(), anchor=w.tmp / "a")
    with pytest.raises(IntegrityError, match="adóptala"):
        late.journal.head()
    late.journal.adopt_anchor()
    assert late.journal.head()[0] == 1
    with pytest.raises(PolicyViolation):
        late.journal.adopt_anchor()
    with pytest.raises(PolicyViolation):
        plain.journal.adopt_anchor()
    (w.tmp / "g.diario").write_text("basura\n")
    fresh = guardian.Keeper(lock, w.tmp / "g.diario", clock=Clock(), anchor=w.tmp / "b")
    with pytest.raises(IntegrityError):
        fresh.journal.adopt_anchor()                                         # no se adopta un diario roto
    assert not (w.tmp / "b").exists()


def test_if_the_anchor_cannot_be_written_nothing_is_handed_out_and_the_journal_stays_usable(w, monkeypatch):
    lock = qsello.Lock.generate("disco")
    f = w.seal(DATA, locks=[lock])
    k = guardian.Keeper(lock, w.tmp / "g.diario", clock=Clock(), anchor=w.tmp / "a")
    k.register(f, w.sender.public_bytes)
    k.enroll(w.requester.public_bytes)
    request = _request_at(w, f)
    proof = _proof(w, k, f, request)

    def boom(*a, **kw):
        raise OSError("medio desconectado")
    monkeypatch.setattr(journal, "atomic_write", boom)
    with pytest.raises(OSError):
        k.release(f, w.sender.public_bytes, request, proof)
    monkeypatch.undo()
    assert k.journal.head()[0] == 3 and json.loads((w.tmp / "a").read_text())["n"] == 2   # el diario va por delante del ancla: válido
    with pytest.raises(PolicyViolation, match="YA se atendió"):
        k.release(f, w.sender.public_bytes, request, proof)                  # la entrega quedó anotada: no se repite
    fresh = _request_at(w, f)
    assert k.release(f, w.sender.public_bytes, fresh, _proof(w, k, f, fresh)) and json.loads((w.tmp / "a").read_text())["n"] == 4


@pytest.mark.parametrize("delta,ok", [(-301, False), (-300, True), (0, True), (10_000, True)])
def test_a_clock_set_back_cannot_write_in_the_journal(w, delta, ok):
    lock, k, clock, path, anchor = _anchored(w)
    clock.t = NOW + delta
    if ok:
        k.enroll(HybridSigPrivateKey.generate().public_bytes)
    else:
        before = path.read_bytes()
        with pytest.raises(PolicyViolation, match="RETROCEDIÓ"):
            k.enroll(HybridSigPrivateKey.generate().public_bytes)
        assert path.read_bytes() == before


def test_setting_the_clock_back_does_not_revive_an_expired_request(w):
    _, f, k, clock = _setup(w)
    request = _request_at(w, f, ttl=600)
    proof = _proof(w, k, f, request)
    clock.t = NOW + 7200
    k.enroll(HybridSigPrivateKey.generate().public_bytes)                    # un apunte posterior a la caducidad
    clock.t = NOW + 100                                                      # el reloj «vuelve» a cuando la solicitud valía
    with pytest.raises(PolicyViolation, match="según el diario"):
        k.release(f, w.sender.public_bytes, request, proof)
    assert k.deliveries() == []
    still_valid = _request_at(w, f, now=NOW + 100, ttl=86_400)              # vigente según el diario, pero el reloj va 2 h atrás: no se puede anotar
    with pytest.raises(PolicyViolation, match="RETROCEDIÓ"):
        k.release(f, w.sender.public_bytes, still_valid, _proof(w, k, f, still_valid))
    assert k.deliveries() == []


# ------------------------------------------------------------------------------------------------ custodio con memoria
def _custodian(w, who="bea", **kw):
    return guardian.Custodian(w.cust[who], w.tmp / f"{who}.diario", clock=kw.pop("clock", Clock()), **kw)


def test_a_custodian_with_memory_serves_each_request_once_and_keeps_the_reason(w):
    f = w.seal(DATA)
    bea = _custodian(w)
    request = _request_at(w, f, reason="revision anual")
    first = bea.contribute(f, w.sender.public_bytes, request)
    assert qsello._check_contribution(qsello.read_header(f, w.sender.public_bytes), first, w.opener)
    for again in (request, json.dumps(json.loads(request), indent=2).encode()):
        with pytest.raises(PolicyViolation, match="YA se atendió"):
            bea.contribute(f, w.sender.public_bytes, again)
    assert bea.contribute(f, w.sender.public_bytes, _request_at(w, f))
    assert [e["reason"] for e in bea.served()] == ["revision anual", "auditoria"]
    assert _custodian(w, "carla").contribute(f, w.sender.public_bytes, request)   # cada custodio tiene SU memoria


def test_a_custodian_records_nothing_when_it_refuses_and_its_journal_belongs_to_its_key(w):
    f = w.seal(DATA, groups=[w.group("a", 1, "bea")])
    stranger = _custodian(w, "carla")
    with pytest.raises(PolicyViolation, match="ningún custodio"):
        stranger.contribute(f, w.sender.public_bytes, _request_at(w, f))
    assert stranger.served() == []
    bea = _custodian(w)
    with pytest.raises(PolicyViolation, match="CADUCADO"):
        _custodian(w, clock=Clock(NOW + 10**6)).contribute(f, w.sender.public_bytes, _request_at(w, f))
    bea.contribute(f, w.sender.public_bytes, _request_at(w, f))
    thief = guardian.Custodian(w.cust["carla"], w.tmp / "bea.diario", clock=Clock())
    with pytest.raises(IntegrityError):
        thief.served()
    text = (w.tmp / "bea.diario").read_text()
    assert w.cust["bea"].seed().hex() not in text


def test_a_custodian_anchor_detects_a_forgotten_delivery(w):
    f = w.seal(DATA)
    bea = _custodian(w, anchor=w.tmp / "bea.ancla")
    request = _request_at(w, f)
    bea.contribute(f, w.sender.public_bytes, request)
    (w.tmp / "bea.diario").write_text("")
    with pytest.raises(IntegrityError, match="anclada"):
        bea.contribute(f, w.sender.public_bytes, request)


# ------------------------------------------------------------------------------------------------ resguardos
@pytest.mark.parametrize("level", [STANDARD, HIGH])
def test_custodians_and_keeper_can_decide_from_a_stub_without_the_body(tmp_path, level):
    w = World(tmp_path, level)
    lock = qsello.Lock.generate("l")
    data = os.urandom(3 * qsello.CHUNK + 11)
    f = w.seal(data, locks=[lock])
    stub = w.tmp / "doc.resguardo"
    stub.write_bytes(qsello.make_stub(f, w.sender.public_bytes))
    hd, full = qsello.read_header(stub, w.sender.public_bytes), qsello.read_header(f, w.sender.public_bytes)
    assert hd.stub and not full.stub and hd.digest == full.digest and stub.stat().st_size < 20_000 + level.sig_len * 2
    assert qsello.verify_file(stub, w.sender.public_bytes)[1:] == qsello.verify_file(f, w.sender.public_bytes)[1:]
    request = w.request(stub)
    parts = [qsello.contribute(stub, w.sender.public_bytes, w.cust[n], request) for n in ("bea", "carla", "eva")]
    k = guardian.Keeper(lock, w.tmp / "g.diario")
    k.register(stub, w.sender.public_bytes)
    k.enroll(w.requester.public_bytes)
    token = k.release(stub, w.sender.public_bytes, request, _proof(w, k, stub, request))
    assert w.open(f, parts, tokens=[token])[0] == data                       # lo decidido sobre el resguardo abre el archivo COMPLETO
    with pytest.raises(PolicyViolation, match="resguardo"):
        w.open(stub, parts, out="no.bin", tokens=[token])
    with pytest.raises(PolicyViolation, match="ya es un resguardo"):
        qsello.make_stub(stub, w.sender.public_bytes)


def test_a_stub_cannot_be_altered_cut_extended_or_made_from_a_bad_file(w):
    f = w.seal(DATA, groups=[w.group("a", 1, "bea")])
    raw = qsello.make_stub(f, w.sender.public_bytes)
    bad = w.tmp / "bad.resguardo"
    sig = w.sender.level.sig_len
    positions = [0, 7, 8, 14, 18, len(raw) - 1, len(raw) - sig, len(raw) - sig - 1, len(raw) - sig - 9, len(raw) - sig - 20, len(raw) - 2 * sig - 41]
    cases = [raw[:p] + bytes([raw[p] ^ 1]) + raw[p + 1:] for p in positions] + [raw[:-1], raw + b"x", raw[: len(raw) - sig], raw[8:], raw[:8]]
    for blob in cases:
        bad.write_bytes(blob)
        with pytest.raises(QCEError):
            qsello.verify_file(bad, w.sender.public_bytes)
    short = f.read_bytes()[: qsello.read_header(f, w.sender.public_bytes).payload_start]   # resguardo «firmado» con un cuerpo imposible
    digest = qsello.read_header(f, w.sender.public_bytes).digest
    tiny = bytes(32) + (3).to_bytes(8, "big")
    bad.write_bytes(qsello.STUB_MAGIC + short + tiny + w.sender.sign(digest + tiny, qsello.CTX_FILE))
    with pytest.raises(MalformedMessage, match="imposible"):
        qsello.verify_file(bad, w.sender.public_bytes)
    body = bytearray(f.read_bytes())
    body[-sig - 1] ^= 1
    f.write_bytes(body)
    with pytest.raises(AuthenticationFailure):
        qsello.make_stub(f, w.sender.public_bytes)


# ------------------------------------------------------------------------------------------------ quórum robusto frente a un reparto defectuoso
@pytest.mark.parametrize("bad_x", [1, 2, 4])
def test_one_bad_share_from_the_dealer_does_not_block_a_quorum_with_spare_members(w, bad_x):
    groups = [w.group("a", 2, "bea", "carla", "dani", "eva")]
    f = w.seal(DATA, groups=groups, _split=corrupting_split(2, 4, bad_x))
    names = ("bea", "carla", "dani", "eva")
    parts = {n: w.part(f, n) for n in names}
    outcomes = {}
    for r in (2, 3, 4):
        for subset in itertools.combinations(names, r):
            try:
                outcomes[subset] = w.open(f, [parts[n] for n in subset])[0]
            except AuthenticationFailure:
                outcomes[subset] = None
    bad = names[bad_x - 1]
    for subset, result in outcomes.items():
        good_enough = len([n for n in subset if n != bad]) >= 2
        assert result == (DATA if good_enough else None), subset             # o el contenido original o fallo: nunca otra cosa


def test_two_bad_shares_are_also_overcome_and_the_search_is_bounded(w, monkeypatch):
    def two_bad(secret, k, n):
        shares = shamir.split(secret, k, n)
        if (k, n) == (2, 5):
            for x in (1, 2):
                shares[x] = os.urandom(32)
        return shares
    f = w.seal(DATA, groups=[w.group("a", 2, "bea", "carla", "dani", "eva", "fer")], _split=two_bad)
    parts = [w.part(f, n) for n in ("bea", "carla", "dani", "eva")]
    assert w.open(f, parts)[0] == DATA
    monkeypatch.setattr(qsello, "MAX_SUBSETS", 2)
    with pytest.raises(AuthenticationFailure, match="INCONSISTENTE"):
        w.open(f, parts, out="no.bin")


def test_a_bad_group_does_not_block_when_other_groups_suffice(w):
    groups = [w.group("a", 2, "bea", "carla"), w.group("b", 1, "dani")]

    def broken_first(secret, k, n):
        shares = shamir.split(secret, k, n)
        if (k, n) == (2, 2):
            shares[1] = os.urandom(32)
        return shares
    f = w.seal(DATA, groups=groups, need=1, _split=broken_first)
    assert w.open(f, [w.part(f, n) for n in ("bea", "carla", "dani")])[0] == DATA


# ------------------------------------------------------------------------------------------------ línea de comandos, de extremo a extremo
def test_the_whole_ceremony_from_the_command_line(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    phrase = tmp_path / "frase"
    phrase.write_text(PHRASE + "\n")
    phrase.chmod(0o600)

    def run(*argv, ok=True):
        code = cli.main([*argv, "--passphrase-file", "frase"])
        assert (code == 0) == ok, (argv, capsys.readouterr())
        return capsys.readouterr()
    for kind, name in (("emisor", "ana"), ("emisor", "gil"), ("custodio", "bea"), ("custodio", "carla"), ("custodio", "apertura"), ("candado", "plazo")):
        run("keygen", kind, name)
    assert "ya existe" in run("keygen", "emisor", "ana", ok=False).err and "ya existe" in run("keygen", "candado", "plazo", ok=False).err
    assert stat.S_IMODE((tmp_path / "ana.key").stat().st_mode) == 0o600 and "seed" not in (tmp_path / "ana.key").read_text()
    (tmp_path / "doc.txt").write_text("acta con plazo")
    sp, lk = ["--sender-pub", "ana.pub"], ["--lock", "plazo.candado", "--journal", "g.diario", "--anchor", "g.ancla"]
    run("seal", "doc.txt", "d.qsel", "--sender", "ana.key", "--opener", "gil.pub", "--group", "dir:2:bea.pub,carla.pub", "--lock", "plazo.candado")
    assert '"resguardo": false' in run("info", "d.qsel", *sp).out
    run("stub", "d.qsel", *sp, "--out", "d.resguardo")
    assert '"resguardo": true' in run("info", "d.resguardo", *sp).out
    run("split-lock", "--lock", "plazo.candado", "--k", "2", "--n", "3", "--out-prefix", "parte")
    shares = ["--share", "parte-3.parte", "--share", "parte-1.parte"]
    run("guardian", "register", "d.resguardo", *sp, *shares, "--journal", "g.diario", "--anchor", "g.ancla")
    run("guardian", "enroll", *lk, "--requester", "gil.pub", "--out", "gil.secreto")
    assert "ya existe" in run("guardian", "enroll", *lk, "--requester", "gil.pub", "--out", "gil.secreto", ok=False).err
    run("request", "d.qsel", *sp, "--key", "gil.key", "--to", "apertura.pub", "--reason", "revision legal", "--out", "s.req", "--ttl-hours", "2")
    for who in ("bea", "carla"):
        out = run("contribute", "d.resguardo", *sp, "--key", f"{who}.key", "--request", "s.req", "--out", f"{who}.part", "--anchor", f"{who}.ancla").out
        assert "motivo: revision legal" in out and (tmp_path / f"{who}.diario").exists()
    assert "YA se atendió" in run("contribute", "d.qsel", *sp, "--key", "bea.key", "--request", "s.req", "--out", "otra.part", ok=False).err
    base = ["open", "d.qsel", "out.txt", *sp, "--key", "apertura.key", "bea.part", "carla.part"]
    assert "falta la ficha del candado: plazo" in run(*base, ok=False).err
    run("prove", "d.qsel", *sp, "--request", "s.req", "--secret", "gil.secreto", "--out", "s.prueba")
    release = ["guardian", "release", "d.resguardo", *sp, *lk, "--request", "s.req", "--proof", "s.prueba", "--out", "d.ficha"]
    pin = run("guardian", "head", *lk).out.strip()
    out = run(*release, "--pin", pin)
    master = keys.load_secret(tmp_path / "plazo.candado", "candado", PHRASE)[1]
    assert master.hex() not in out.out and stat.S_IMODE((tmp_path / "d.ficha").stat().st_mode) == 0o600
    run(*base, "--token", "d.ficha")
    assert (tmp_path / "out.txt").read_text() == "acta con plazo"
    assert "YA se atendió" in run(*release, ok=False).err
    run("guardian", "withdraw", "d.resguardo", *sp, *lk)
    run("guardian", "revoke", *lk, "--requester", "gil.pub")
    assert "fijada" in run("guardian", "head", *lk, "--pin", "99:" + "00" * 32, ok=False).err
    (tmp_path / "g.ancla").unlink()
    assert "falta el ancla" in run("guardian", "head", *lk, ok=False).err
    run("guardian", "adopt-anchor", *lk)
    assert "una de las dos" in run("guardian", "head", "--journal", "g.diario", ok=False).err
    assert "una de las dos" in run("guardian", "head", *lk, *shares, ok=False).err
    assert "faltan partes" in run("guardian", "head", "--share", "parte-1.parte", "--journal", "g.diario", ok=False).err


def test_the_command_line_refuses_a_passphrase_file_others_can_read_and_wrong_files(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    phrase = tmp_path / "frase"
    phrase.write_text(PHRASE)
    for mode in (0o644, 0o640, 0o604):
        phrase.chmod(mode)
        assert cli.main(["keygen", "emisor", "ana", "--passphrase-file", "frase"]) == 1
        assert "legible por otros" in capsys.readouterr().err and not (tmp_path / "ana.key").exists()
    phrase.chmod(0o600)
    assert cli.main(["keygen", "emisor", "ana", "--passphrase-file", "frase"]) == 0
    (tmp_path / "x").write_text("x")
    assert cli.main(["seal", "x", "x.qsel", "--sender", "ana.key", "--opener", "ana.pub", "--group", "g:1:ana.pub", "--passphrase-file", "frase"]) == 1
    assert "se esperaba una clave pública" in capsys.readouterr().err and not (tmp_path / "x.qsel").exists()
    (tmp_path / "b.pub").write_text("{}")
    assert cli.main(["keygen", "emisor", "b", "--passphrase-file", "frase"]) == 1
    assert not (tmp_path / "b.key").exists()


def test_without_a_passphrase_file_the_phrase_is_asked_twice_and_must_match(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    answers = iter([PHRASE, PHRASE + "x"])
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: next(answers))
    assert cli.main(["keygen", "emisor", "ana"]) == 1 and "no coinciden" in capsys.readouterr().err
    answers = iter([PHRASE, PHRASE])
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: next(answers))
    assert cli.main(["keygen", "emisor", "ana"]) == 0 and (tmp_path / "ana.key").exists()


def test_the_module_can_be_run_as_a_program(tmp_path):
    import subprocess
    import sys
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    r = subprocess.run([sys.executable, "-m", "qce.sealed", "--help"], capture_output=True, text=True, cwd=tmp_path, env={**os.environ, "PYTHONPATH": str(root)}, timeout=60)
    assert r.returncode == 0 and "split-lock" in r.stdout and "guardian" in r.stdout
