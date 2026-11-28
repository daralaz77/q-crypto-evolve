"""Sobre sellado (qce.sealed): quórum, candado, guardián. Se llama `test_00_…` para que corra primero: en la prueba de mutación un control roto se detecta en segundos."""
import base64
import hashlib
import itertools
import json
import os
import time
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag

from qce.core.errors import AuthenticationFailure, IntegrityError, MalformedMessage, PolicyViolation, QCEError
from qce.pqc.hybrid import HIGH, STANDARD, HybridKemPrivateKey, HybridSigPrivateKey
from qce.pqc.xwing import XWingPrivateKey
from qce.sealed import envelope as qsello
from qce.sealed import journal, shamir
from qce.sealed import keeper as guardian


class World:
    def __init__(self, tmp, level=STANDARD):
        self.tmp, self.level = tmp, level
        self.sender = HybridSigPrivateKey.generate(level)
        self.kem = qsello.SUITES[level.name]
        self.cust = {n: self.kem.generate() for n in ("bea", "carla", "dani", "eva", "fer")}
        self.opener = self.kem.generate()
        self.requester = HybridSigPrivateKey.generate(level)

    def group(self, name, k, *names):
        return qsello.Group(name, k, tuple(self.cust[n].public_bytes for n in names))

    def groups(self):
        return [self.group("direccion", 2, "bea", "carla", "dani"), self.group("legal", 1, "eva", "fer")]

    def seal(self, data: bytes, name="doc", groups=None, need=None, **kw):
        src, dst = self.tmp / f"{name}.bin", self.tmp / f"{name}.qsel"
        src.write_bytes(data)
        qsello.seal(src, dst, self.sender, groups or self.groups(), [self.requester.public_bytes], need, **kw)
        return dst

    def request(self, f, opener=None, requester=None, reason="auditoria anual"):
        return qsello.request_open(f, self.sender.public_bytes, requester or self.requester, (opener or self.opener).public_bytes, reason)

    def part(self, f, who, opener=None):
        return qsello.contribute(f, self.sender.public_bytes, self.cust[who], self.request(f, opener))

    def open(self, f, parts, out="salida.bin", opener=None, tokens=None):
        dst = self.tmp / out
        rep = qsello.open_sealed(f, dst, self.sender.public_bytes, opener or self.opener, parts, tokens)
        return dst.read_bytes(), rep


@pytest.fixture(scope="module")
def keys(tmp_path_factory):
    return World(tmp_path_factory.mktemp("w"))


@pytest.fixture
def w(keys, tmp_path):
    keys.tmp = tmp_path
    return keys


DATA = os.urandom(1000)


# ------------------------------------------------------------------------------------------------ Shamir
def test_gf256_multiplication_matches_the_aes_field():
    assert shamir._mul(0x57, 0x83) == 0xC1 and shamir._mul(0x57, 0x13) == 0xFE     # ejemplos de FIPS 197 §4.2
    assert all(shamir._mul(a, shamir._inv(a)) == 1 for a in range(1, 256))


@pytest.mark.parametrize("k,n", [(1, 1), (1, 3), (2, 3), (3, 5), (5, 5), (4, 16)])
def test_every_quorum_recovers_and_fewer_does_not(k, n):
    secret = os.urandom(32)
    shares = shamir.split(secret, k, n)
    for subset in itertools.islice(itertools.combinations(shares, k), 60):
        assert shamir.combine({x: shares[x] for x in subset}) == secret
    if k > 1:
        for subset in itertools.islice(itertools.combinations(shares, k - 1), 60):
            assert shamir.combine({x: shares[x] for x in subset}) != secret


# ------------------------------------------------------------------------------------------------ ida y vuelta
@pytest.mark.parametrize("size", [0, 1, qsello.CHUNK - 1, qsello.CHUNK, qsello.CHUNK + 1, 3 * qsello.CHUNK, 3 * qsello.CHUNK + 7])
def test_round_trip_at_every_chunk_boundary(w, size):
    data = os.urandom(size)
    f = w.seal(data)
    out, rep = w.open(f, [w.part(f, n) for n in ("bea", "dani", "fer")])
    assert out == data and rep["rejected"] == []


@pytest.mark.parametrize("level", [STANDARD, HIGH])
@pytest.mark.parametrize("aead", sorted(qsello.AEADS))
def test_both_levels_and_both_aeads(tmp_path, level, aead):
    w = World(tmp_path, level)
    f = w.seal(DATA, aead=aead)
    assert w.open(f, [w.part(f, n) for n in ("carla", "dani", "eva")])[0] == DATA


def test_every_authorised_combination_opens_and_every_other_one_fails(w):
    f = w.seal(DATA)
    parts = {n: w.part(f, n) for n in w.cust}
    for r in range(len(parts) + 1):
        for subset in itertools.combinations(parts, r):
            allowed = len({"bea", "carla", "dani"} & set(subset)) >= 2 and bool({"eva", "fer"} & set(subset))
            if allowed:
                assert w.open(f, [parts[n] for n in subset])[0] == DATA
            else:
                with pytest.raises(PolicyViolation, match="quórum insuficiente"):
                    w.open(f, [parts[n] for n in subset], out="no.bin")
                assert not (w.tmp / "no.bin").exists()


def test_a_threshold_over_groups_lets_any_two_of_three_departments_open(w):
    groups = [w.group("a", 1, "bea"), w.group("b", 1, "carla"), w.group("c", 1, "dani")]
    f = w.seal(DATA, groups=groups, need=2)
    for pair in itertools.combinations(("bea", "carla", "dani"), 2):
        assert w.open(f, [w.part(f, n) for n in pair])[0] == DATA
    with pytest.raises(PolicyViolation):
        w.open(f, [w.part(f, "bea")], out="no.bin")


def test_the_same_contribution_twice_counts_once(w):
    f = w.seal(DATA)
    bea = w.part(f, "bea")
    with pytest.raises(PolicyViolation, match="1/2"):
        w.open(f, [bea, bea, w.part(f, "eva")])


# ------------------------------------------------------------------------------------------------ HYP-0001: participaciones defectuosas
def forged_contribution(w, f, who, share):
    """Un custodio malicioso (o un tercero) fabrica una contribución bien cifrada pero con una participación falsa para SU posición."""
    hd = qsello.read_header(f, w.sender.public_bytes)
    gi, x, _, _ = qsello._slot(hd, w.cust[who])
    ss, ct = hd.suite.encapsulate(w.opener.public_bytes)
    ctx = qsello._contrib_context(hd, gi, x, w.opener.public_bytes)
    box = qsello.AESGCM(qsello.hkdf(ss, ctx)).encrypt(qsello.ZERO_NONCE, share, ctx)
    return json.dumps({"v": 3, "file": hd.digest.hex(), "g": gi, "x": x, "ct": qsello._b64(ct), "box": qsello._b64(box)}).encode(), (gi, x)


def test_a_false_share_is_identified_and_the_file_still_opens_with_the_rest(w):
    f = w.seal(DATA)
    for trial in range(30):
        bad, slot = forged_contribution(w, f, "carla", os.urandom(32))
        out, rep = w.open(f, [w.part(f, "bea"), bad, w.part(f, "dani"), w.part(f, "eva")])
        assert out == DATA and [r["index"] for r in rep["rejected"]] == [1] and "INCORRECTA" in rep["rejected"][0]["reason"], trial
        assert slot not in rep["used"]


def test_when_the_false_share_leaves_no_quorum_the_error_names_it(w):
    f = w.seal(DATA)
    bad, _ = forged_contribution(w, f, "carla", os.urandom(32))
    with pytest.raises(PolicyViolation, match="contribución 1: participación INCORRECTA"):
        w.open(f, [w.part(f, "bea"), bad, w.part(f, "eva")])


def test_a_contribution_is_bound_to_one_opening_session_and_one_file(w):
    f, other = w.seal(DATA, "uno"), w.seal(DATA, "dos")
    intruder = w.kem.generate()
    for_intruder = w.part(f, "bea", opener=intruder)
    with pytest.raises(PolicyViolation, match="no es para esta apertura"):
        w.open(f, [for_intruder, w.part(f, "carla"), w.part(f, "eva")])
    with pytest.raises(PolicyViolation, match="OTRO archivo"):
        w.open(f, [w.part(other, "bea"), w.part(f, "carla"), w.part(f, "eva")])


@pytest.mark.parametrize("field,value", [("g", 2), ("x", 3), ("g", 99), ("x", 0), ("x", True), ("v", 1), ("v", True)])
def test_a_contribution_moved_to_another_slot_is_rejected(w, field, value):
    f = w.seal(DATA)
    c = json.loads(w.part(f, "bea"))
    c[field] = value
    with pytest.raises(PolicyViolation):
        w.open(f, [json.dumps(c).encode(), w.part(f, "carla"), w.part(f, "eva")])


@pytest.mark.parametrize("junk", [b"", b"[]", b"{", b'{"v":1}', b"\xff", b'{"v":1,"v":1}'])
def test_junk_contributions_are_reported_not_crashed(w, junk):
    f = w.seal(DATA)
    out, rep = w.open(f, [junk, w.part(f, "bea"), w.part(f, "carla"), w.part(f, "eva")])
    assert out == DATA and rep["rejected"][0]["index"] == 0


# ------------------------------------------------------------------------------------------------ HYP-0002: reparto inconsistente (emisor malicioso)
def corrupting_split(target_k, target_n, bad_x):
    def _split(secret, k, n):
        shares = shamir.split(secret, k, n)
        if (k, n) == (target_k, target_n):
            shares[bad_x] = bytes(b ^ 1 for b in shares[bad_x])  # participación fuera del polinomio, con compromiso «correcto»
        return shares
    return _split


def test_a_malicious_dealer_cannot_make_two_quorums_read_different_files(w):
    f = w.seal(DATA, _split=corrupting_split(2, 3, 2))
    results = []
    for pair in itertools.combinations(("bea", "carla", "dani"), 2):
        try:
            results.append(w.open(f, [w.part(f, n) for n in (*pair, "eva")])[0])
        except AuthenticationFailure as exc:
            assert "INCONSISTENTE" in str(exc) and "direccion" in str(exc) and "carla" in pair
            results.append(None)
    assert results.count(DATA) == 1 and results.count(None) == 2     # o el mismo contenido, o fallo: nunca otro contenido


def test_inconsistent_shares_between_groups_are_caught_by_the_key_commitment(w):
    groups = [w.group("a", 1, "bea"), w.group("b", 1, "carla"), w.group("c", 1, "dani")]
    f = w.seal(DATA, groups=groups, need=2, _split=corrupting_split(2, 3, 3))
    assert w.open(f, [w.part(f, "bea"), w.part(f, "carla")])[0] == DATA
    with pytest.raises(AuthenticationFailure, match="entre grupos"):
        w.open(f, [w.part(f, "bea"), w.part(f, "dani")])


# ------------------------------------------------------------------------------------------------ HYP-0003: manipulación
def _fails(w, f, parts):
    out = w.tmp / "manipulado.out"
    with pytest.raises(QCEError):
        qsello.open_sealed(f, out, w.sender.public_bytes, w.opener, parts)
    assert not out.exists() and not list(w.tmp.glob(".manipulado.out-*"))


def test_flipping_any_single_byte_prevents_opening(w):
    f = w.seal(b"contenido breve", groups=[w.group("a", 1, "bea")])
    parts = [w.part(f, "bea")]
    original = f.read_bytes()
    bad = w.tmp / "bad.qsel"
    for pos in range(len(original)):
        mutated = bytearray(original)
        mutated[pos] ^= 0x01
        bad.write_bytes(mutated)
        _fails(w, bad, parts)


def test_truncation_extension_reordering_and_splicing_are_refused(w):
    data = os.urandom(3 * qsello.CHUNK + 5)
    f, g = w.seal(data, "uno"), w.seal(data, "dos")
    parts = [w.part(f, n) for n in ("bea", "carla", "eva")]
    raw, other = f.read_bytes(), g.read_bytes()
    hd = qsello.read_header(f, w.sender.public_bytes)
    s, c, sl = hd.payload_start, qsello.CHUNK + qsello.TAG, hd.level.sig_len
    head, body, sig = raw[:s], raw[s:-sl], raw[-sl:]
    cases = {
        "truncado al final de un trozo": head + body[: 2 * c] + sig, "sin el último trozo": head + body[: 3 * c] + sig,
        "trozos intercambiados": head + body[c: 2 * c] + body[:c] + body[2 * c:] + sig, "trozo duplicado": head + body[:c] + body + sig,
        "bytes añadidos": raw + b"x", "sin firma final": head + body, "firma de otro archivo": head + body + other[-sl:],
        "cuerpo de otro archivo": head + other[s:-sl] + sig, "solo cabecera": head, "vacío": b"", "magia sola": raw[:6],
    }
    bad = w.tmp / "bad.qsel"
    for blob in cases.values():
        bad.write_bytes(blob)
        _fails(w, bad, parts)
    for cut in list(range(0, s + 40, 97)) + [len(raw) - 1, len(raw) - sl, len(raw) - sl - 1]:
        bad.write_bytes(raw[:cut])
        _fails(w, bad, parts)


def test_a_file_signed_by_someone_else_is_refused_before_a_custodian_releases_anything(w):
    f = w.seal(DATA)
    real_sender = w.sender
    w.sender = HybridSigPrivateKey.generate()
    forged = w.seal(DATA, "falso")
    w.sender = real_sender
    with pytest.raises(AuthenticationFailure):
        w.part(forged, "bea")                       # el custodio fija la clave del emisor: no libera nada para un archivo ajeno
    assert w.part(f, "bea")


def test_a_custodian_who_is_not_in_the_file_cannot_contribute(w):
    f = w.seal(DATA, groups=[w.group("a", 1, "bea")])
    with pytest.raises(PolicyViolation, match="ningún custodio"):
        w.part(f, "carla")


def test_an_existing_output_is_not_destroyed_by_a_failed_opening(w):
    f = w.seal(DATA)
    out = w.tmp / "existente.txt"
    out.write_text("no me borres")
    with pytest.raises(PolicyViolation):
        qsello.open_sealed(f, out, w.sender.public_bytes, w.opener, [w.part(f, "bea")])
    assert out.read_text() == "no me borres"


# ------------------------------------------------------------------------------------------------ cabecera estricta (emisor defectuoso)
def _signed_with_header(w, mutate):
    f = w.seal(DATA)
    hd = qsello.read_header(f, w.sender.public_bytes)
    obj = json.loads(hd.raw)
    mutate(obj)
    raw = json.dumps(obj).encode()
    prefix = qsello.MAGIC + len(raw).to_bytes(4, "big") + raw
    bad = w.tmp / "cabecera.qsel"
    bad.write_bytes(prefix + w.sender.sign(prefix, qsello.CTX_HEADER) + b"x" * 64)
    return bad


_LOCK = {"id": "ab" * 16, "label": "x", "com": "0" * 64}
MUTATIONS = {
    "candado repetido": lambda o: o.update(locks=[_LOCK, _LOCK]), "demasiados candados": lambda o: o.update(locks=[dict(_LOCK, id=f"{i:032x}") for i in range(5)]),
    "id de candado corto": lambda o: o.update(locks=[dict(_LOCK, id="ab")]), "etiqueta de candado con control": lambda o: o.update(locks=[dict(_LOCK, label="a\nb")]),
    "compromiso de candado mal formado": lambda o: o.update(locks=[dict(_LOCK, com="z")]), "campo extra en candado": lambda o: o.update(locks=[dict(_LOCK, key="0")]),
    "candados que no son lista": lambda o: o.update(locks={}),
    "campo extra": lambda o: o.update(extra=1), "sin compromiso": lambda o: o.pop("commit"), "umbral 0": lambda o: o["groups"][0].update(k=0),
    "umbral mayor que miembros": lambda o: o["groups"][0].update(k=9), "need 0": lambda o: o.update(need=0), "need de más": lambda o: o.update(need=3),
    "booleano como número": lambda o: o.update(need=True), "custodio repetido": lambda o: o["groups"][1]["members"].append(o["groups"][0]["members"][0]),
    "grupos vacíos": lambda o: o.update(groups=[]), "aead desconocido": lambda o: o.update(aead="NINGUNO"), "nivel cambiado": lambda o: o.update(level="high"), "kem de otro nivel": lambda o: o.update(kem="QCE-X25519-MLKEM1024"), "formato 1": lambda o: o.update(v=1), "formato 2": lambda o: o.update(v=2),
    "otro emisor": lambda o: o.update(sender="0" * 64), "base64 no canónico": lambda o: o["groups"][0]["members"][0].update(box="!!!"),
    "nombre de control": lambda o: o["groups"][0].update(name="a\x00b"), "sin solicitantes": lambda o: o.update(openers=[]),
    "solicitante mal formado": lambda o: o.update(openers=["xyz"]), "demasiados solicitantes": lambda o: o.update(openers=["0" * 64] * 9),
}


@pytest.mark.parametrize("name", sorted(MUTATIONS))
def test_even_a_correctly_signed_header_must_be_strictly_well_formed(w, name):
    bad = _signed_with_header(w, MUTATIONS[name])
    with pytest.raises((MalformedMessage, AuthenticationFailure)):
        qsello.read_header(bad, w.sender.public_bytes)


@pytest.mark.parametrize("bad_policy", [
    lambda w: ([], None), lambda w: ([w.group("a", 2, "bea")], None), lambda w: ([w.group("a", 1, "bea")], 2),
    lambda w: ([w.group("a", 1, "bea"), w.group("b", 1, "bea")], None), lambda w: ([w.group("", 1, "bea")], None),
])
def test_impossible_policies_are_refused_at_sealing_time(w, bad_policy):
    groups, need = bad_policy(w)
    (w.tmp / "x").write_bytes(b"x")
    with pytest.raises(PolicyViolation):
        qsello.seal(w.tmp / "x", w.tmp / "x.qsel", w.sender, groups, [w.requester.public_bytes], need)
    assert not (w.tmp / "x.qsel").exists()


# ------------------------------------------------------------------------------------------------ huecos que destapó la prueba de mutación
def _payload_cipher(w, f, who=("bea", "carla", "eva")):
    """Lo que sabe un quórum tras abrir: el cifrador del cuerpo (sirve para jugar el papel de un INSIDER)."""
    hd = qsello.read_header(f, w.sender.public_bytes)
    shares = {}
    for n in who:
        gi, x, s = qsello._check_contribution(hd, w.part(f, n), w.opener)
        shares[(gi, x)] = s
    secret = qsello.recover_secret(hd, shares)
    return hd, qsello.AEADS[hd.data["aead"]](qsello._payload_key(secret, hd.digest))


def test_each_chunk_uses_its_own_counter_and_only_the_last_one_carries_the_final_mark(w):
    data = bytes(3 * qsello.CHUNK)                                             # tres trozos IDÉNTICOS en claro
    f = w.seal(data)
    hd, cipher = _payload_cipher(w, f)
    c = qsello.CHUNK + qsello.TAG
    body = f.read_bytes()[hd.payload_start: -hd.level.sig_len]
    chunks = [body[i: i + c] for i in range(0, len(body), c)]
    assert len(chunks) == 3 and len(set(chunks)) == 3                          # nonce distinto en cada trozo
    for i, ch in enumerate(chunks):
        nonce = i.to_bytes(11, "big") + (b"\x01" if i == 2 else b"\x00")       # la especificación, reimplementada aquí a propósito
        assert cipher.decrypt(nonce, ch, None) == bytes(qsello.CHUNK)
        with pytest.raises(InvalidTag):
            cipher.decrypt(i.to_bytes(11, "big") + (b"\x00" if i == 2 else b"\x01"), ch, None)


def test_an_insider_who_swaps_the_body_between_verification_and_decryption_gets_nothing_published(w, monkeypatch):
    data = os.urandom(100)
    f = w.seal(data)
    parts = [w.part(f, n) for n in ("bea", "carla", "eva")]
    hd, cipher = _payload_cipher(w, f)
    real = qsello.verify_file

    def verify_then_swap(path, sender_public):
        result = real(path, sender_public)
        raw = bytearray(Path(path).read_bytes())
        end = len(raw) - hd.level.sig_len
        raw[hd.payload_start:end] = cipher.encrypt(bytes(11) + b"\x01", b"X" * 100, None)   # cifrado VÁLIDO bajo la misma clave y nonce
        Path(path).write_bytes(raw)
        return result
    monkeypatch.setattr(qsello, "verify_file", verify_then_swap)
    with pytest.raises(AuthenticationFailure, match="cambió mientras se abría"):
        qsello.open_sealed(f, w.tmp / "cambiado.out", w.sender.public_bytes, w.opener, parts)
    assert not (w.tmp / "cambiado.out").exists() and not list(w.tmp.glob(".cambiado.out-*"))


def test_a_custodian_refuses_to_release_a_share_for_a_file_whose_body_was_altered(w):
    f = w.seal(DATA)
    request = w.request(f)                                                     # solicitud legítima, hecha ANTES de la alteración
    raw = bytearray(f.read_bytes())
    hd = qsello.read_header(f, w.sender.public_bytes)
    raw[hd.payload_start] ^= 1
    f.write_bytes(raw)
    with pytest.raises(AuthenticationFailure):
        qsello.contribute(f, w.sender.public_bytes, w.cust["bea"], request)


def test_a_complete_contribution_with_a_repeated_key_is_rejected(w):
    f = w.seal(DATA)
    blob = w.part(f, "bea")
    twice = blob[:-1] + b', "x": 1}'
    out, rep = w.open(f, [twice, w.part(f, "carla"), w.part(f, "dani"), w.part(f, "eva")])
    assert out == DATA and "repetida" in rep["rejected"][0]["reason"]


def test_a_header_of_another_level_signed_by_this_sender_is_refused(tmp_path):
    std, high = World(tmp_path / "s" if (tmp_path / "s").mkdir() is None else tmp_path), World(tmp_path / "h" if (tmp_path / "h").mkdir() is None else tmp_path, HIGH)
    f = high.seal(DATA)
    obj = json.loads(qsello.read_header(f, high.sender.public_bytes).raw)
    obj["sender"] = qsello.fingerprint(std.sender.public_bytes)                # coherente por dentro (nivel «high»), pero firmada por un emisor «standard»
    raw = json.dumps(obj).encode()
    prefix = qsello.MAGIC + len(raw).to_bytes(4, "big") + raw
    bad = tmp_path / "nivel.qsel"
    bad.write_bytes(prefix + std.sender.sign(prefix, qsello.CTX_HEADER) + b"x" * 64)
    with pytest.raises(AuthenticationFailure, match="no corresponde"):
        qsello.read_header(bad, std.sender.public_bytes)


# ------------------------------------------------------------------------------------------------ HYP-0004: solo un solicitante autorizado obtiene participaciones
def _signed_request(hd, signer, kem_public, reason, issued=None, ttl=3600, nonce=None):
    """Solicitud montada A MANO, saltándose las comprobaciones de quien la crea."""
    issued = int(time.time()) if issued is None else issued
    nonce = os.urandom(16) if nonce is None else nonce
    sig = signer.sign(qsello._request_message(hd.digest, kem_public, signer.public_bytes, reason, issued, issued + ttl, nonce), qsello.CTX_REQUEST)
    return json.dumps({"v": 4, "file": hd.digest.hex(), "kem": qsello._b64(kem_public), "signer": qsello._b64(signer.public_bytes), "reason": reason,
                       "issued": issued, "expires": issued + ttl, "nonce": qsello._b64(nonce), "sig": qsello._b64(sig)}).encode()


def test_an_outsider_cannot_collect_shares_with_their_own_key(w):
    f = w.seal(DATA)
    attacker_sig, attacker_kem = HybridSigPrivateKey.generate(), w.kem.generate()
    with pytest.raises(PolicyViolation, match="no está autorizado"):
        w.request(f, opener=attacker_kem, requester=attacker_sig)
    hd = qsello.read_header(f, w.sender.public_bytes)                          # el atacante se salta la comprobación local y firma a mano
    forged = _signed_request(hd, attacker_sig, attacker_kem.public_bytes, "soy yo")
    with pytest.raises(PolicyViolation, match="NO autorizado"):
        qsello.contribute(f, w.sender.public_bytes, w.cust["bea"], forged)


@pytest.mark.parametrize("field", ["kem", "reason", "signer", "sig", "file", "issued", "expires", "nonce"])
def test_nothing_in_a_signed_request_can_be_swapped(w, field):
    f, other = w.seal(DATA, "uno"), w.seal(DATA, "dos")
    good = json.loads(w.request(f))
    swap = json.loads(w.request(other, opener=w.kem.generate(), reason="otro motivo"))
    if field in ("issued", "expires"):
        swap[field] = good[field] + 60
    if field == "signer":
        swap["signer"] = qsello._b64(HybridSigPrivateKey.generate().public_bytes)
    bad = dict(good, **{field: swap[field]})
    with pytest.raises((PolicyViolation, AuthenticationFailure)):
        qsello.contribute(f, w.sender.public_bytes, w.cust["bea"], json.dumps(bad).encode())
    assert qsello.contribute(f, w.sender.public_bytes, w.cust["bea"], json.dumps(good).encode())


def test_a_request_for_one_file_is_useless_for_another(w):
    f, other = w.seal(DATA, "uno"), w.seal(DATA, "dos")
    with pytest.raises(PolicyViolation, match="OTRO archivo"):
        qsello.contribute(other, w.sender.public_bytes, w.cust["bea"], w.request(f))


@pytest.mark.parametrize("reason", ["", "x" * 501, "línea\ncon salto", "\x1b[2Jborra pantalla"])
def test_the_reason_shown_to_a_custodian_must_be_short_and_printable(w, reason):
    f = w.seal(DATA)
    with pytest.raises(PolicyViolation):
        w.request(f, reason=reason)


def test_sealing_requires_at_least_one_authorized_requester(w):
    (w.tmp / "x").write_bytes(b"x")
    for openers in ([], [b"corta"], [w.requester.public_bytes] * 9):
        with pytest.raises(PolicyViolation):
            qsello.seal(w.tmp / "x", w.tmp / "x.qsel", w.sender, [w.group("a", 1, "bea")], openers)


@pytest.mark.parametrize("reason", ["", "x" * 501, "línea\ncon salto", "\x1b[2Jborra pantalla"])
def test_a_custodian_also_filters_the_reason_even_if_an_authorized_requester_signs_it(w, reason):
    f = w.seal(DATA)
    hd = qsello.read_header(f, w.sender.public_bytes)
    r = w.requester
    blob = _signed_request(hd, r, w.opener.public_bytes, reason)                 # solicitante autorizado pero malicioso
    with pytest.raises(MalformedMessage, match="motivo"):
        qsello.contribute(f, w.sender.public_bytes, w.cust["bea"], blob)


# ------------------------------------------------------------------------------------------------ v0.3: X-Wing y agilidad sin degradación
def test_the_standard_level_uses_xwing_and_the_high_level_the_qce_1024_hybrid(tmp_path):
    for level, kem, cls in ((STANDARD, "X-Wing-draft11", XWingPrivateKey), (HIGH, "QCE-X25519-MLKEM1024", HybridKemPrivateKey)):
        (tmp_path / level.name).mkdir()
        w = World(tmp_path / level.name, level)
        assert all(isinstance(k, cls) for k in w.cust.values())
        f = w.seal(DATA)
        d = qsello.read_header(f, w.sender.public_bytes).describe()
        assert d["kem"] == kem and w.open(f, [w.part(f, n) for n in ("bea", "carla", "eva")])[0] == DATA


@pytest.mark.parametrize("role", ["custodio", "apertura"])
def test_a_private_key_of_the_other_kem_with_the_same_length_is_refused_by_type(w, role):
    wrong = HybridKemPrivateKey.generate(STANDARD)                             # misma longitud pública que X-Wing (1216), otro formato y otro combinador
    assert len(wrong.public_bytes) == w.kem.pk_len
    f = w.seal(DATA)
    with pytest.raises(PolicyViolation, match="otro KEM"):
        if role == "custodio":
            qsello.contribute(f, w.sender.public_bytes, wrong, w.request(f))
        else:
            qsello.open_sealed(f, w.tmp / "x.out", w.sender.public_bytes, wrong, [])


def test_sealing_to_a_public_key_of_the_other_standard_kem_fails_closed_instead_of_producing_an_unopenable_file(w):
    """La API recibe bytes: una clave pública del híbrido estándar de QCE mide igual que una de X-Wing. La comprobación de la clave ML-KEM (FIPS 203) la rechaza."""
    (w.tmp / "x").write_bytes(b"x")
    for _ in range(40):
        wrong = HybridKemPrivateKey.generate(STANDARD).public_bytes
        with pytest.raises(QCEError):
            qsello.seal(w.tmp / "x", w.tmp / "x.qsel", w.sender, [qsello.Group("g", 1, (wrong,))], [w.requester.public_bytes])
        assert not (w.tmp / "x.qsel").exists()


# ------------------------------------------------------------------------------------------------ v0.4: candado simétrico (HYP-0008 y HYP-0009)
def _attacker_with_every_private_key(w, f):
    """Juega el papel de quien ROMPE la criptografía de clave pública: abre todas las participaciones de la cabecera y reconstruye el secreto del quórum."""
    hd = qsello.read_header(f, w.sender.public_bytes)
    sid, shares = bytes.fromhex(hd.data["sid"]), {}
    for g, group in enumerate(hd.data["groups"], start=1):
        for x, m in enumerate(group["members"], start=1):
            key = next(k for k in w.cust.values() if qsello.fingerprint(k.public_bytes) == m["id"])
            ss = key.decapsulate(base64.b64decode(m["ct"]))
            wk = qsello._wrap_key(ss, sid, g, x, m["id"], hd.data["sender"], qsello._policy_digest(hd.data))
            shares[(g, x)] = qsello.AESGCM(wk).decrypt(qsello.ZERO_NONCE, base64.b64decode(m["box"]), bytes.fromhex(m["com"]))
    return hd, qsello.recover_secret(hd, shares)


def _decrypts(w, f, hd, payload_key):
    body = f.read_bytes()[hd.payload_start: -hd.level.sig_len]
    try:
        return qsello.AEADS[hd.data["aead"]](payload_key).decrypt(bytes(11) + b"\x01", body, None)
    except InvalidTag:
        return None


def test_control_without_a_lock_breaking_the_public_key_layer_reads_the_file(w):
    """Control positivo: sin candado, el atacante simulado SÍ lee. Si esto fallara, la prueba siguiente no probaría nada."""
    f = w.seal(DATA)
    hd, secret = _attacker_with_every_private_key(w, f)
    assert _decrypts(w, f, hd, qsello._payload_key(secret, hd.digest)) == DATA


def test_with_a_lock_every_private_key_in_the_world_is_still_not_enough(w):
    lock = qsello.Lock.generate("caja-fuerte")
    f = w.seal(DATA, locks=[lock])
    hd, secret = _attacker_with_every_private_key(w, f)
    public = hd.data["locks"][0]
    guesses = [(), (bytes(32),), (os.urandom(32),), (bytes.fromhex(public["com"]),), (bytes.fromhex(public["id"]) * 2,),
               (qsello.Lock.generate("otra").file_key(bytes.fromhex(hd.data["sid"])),)]
    assert all(_decrypts(w, f, hd, qsello._payload_key(secret, hd.digest, g)) is None for g in guesses)
    assert _decrypts(w, f, hd, qsello._payload_key(secret, hd.digest, (lock.file_key(bytes.fromhex(hd.data["sid"])),))) == DATA   # con la ficha, sí
    header = f.read_bytes()[: hd.payload_start]
    assert lock.key not in header and lock.key.hex().encode() not in header and base64.b64encode(lock.key) not in header


def _keeper(w, lock, name=None, clock=time.time):
    """Guardián con el solicitante de la prueba ya dado de alta."""
    k = guardian.Keeper(lock, w.tmp / f"{name or lock.ident.hex()[:8]}.diario", clock=clock)
    if not k.journal.path.exists():
        k.enroll(w.requester.public_bytes)
    return k


def _proof(w, k, f, request):
    ident = qsello.inspect_request(qsello.read_header(f, w.sender.public_bytes), request, now=json.loads(request)["issued"]).ident
    return guardian.prove(ident, k.requester_secret(qsello.fingerprint(w.requester.public_bytes)))


def _token(w, f, lock, opener=None):
    k = _keeper(w, lock)
    if not k._state(k.journal.read())[0].get(qsello.read_header(f, w.sender.public_bytes).digest.hex()):
        k.register(f, w.sender.public_bytes)
    request = w.request(f, opener)
    return k.release(f, w.sender.public_bytes, request, _proof(w, k, f, request))


def test_a_locked_file_opens_only_with_quorum_and_every_token(w):
    a, b = qsello.Lock.generate("caja-fuerte"), qsello.Lock.generate("plazo-2031")
    f = w.seal(DATA, locks=[a, b])
    parts = [w.part(f, n) for n in ("bea", "carla", "eva")]
    ta, tb = _token(w, f, a), _token(w, f, b)
    assert w.open(f, parts, tokens=[ta, tb])[0] == DATA and w.open(f, parts, out="r.bin", tokens=[tb, ta])[0] == DATA   # el orden de las fichas no importa
    for given, missing in (([], "caja-fuerte, plazo-2031"), ([ta], "plazo-2031"), ([tb], "caja-fuerte"), ([ta, ta], "plazo-2031")):
        with pytest.raises(PolicyViolation, match=f"falta la ficha del candado: {missing}"):
            w.open(f, parts, out="no.bin", tokens=given)
    with pytest.raises(PolicyViolation, match="quórum"):
        w.open(f, parts[:1], out="no.bin", tokens=[ta, tb])
    assert not (w.tmp / "no.bin").exists()


def test_destroying_the_master_lock_leaves_files_without_an_issued_token_closed_forever(w):
    """«Destruir» = que nadie conserve la clave maestra. Con quórum COMPLETO y ninguna ficha emitida no hay nada que dar a quien abre."""
    lock = qsello.Lock.generate("plazo")
    already, never = w.seal(DATA, "uno", locks=[lock]), w.seal(DATA, "dos", locks=[lock])
    issued = _token(w, already, lock)
    del lock                                                                  # la maestra deja de existir para el resto de la prueba
    every = [w.part(never, n) for n in w.cust]
    with pytest.raises(PolicyViolation, match="falta la ficha"):
        w.open(never, every, out="no.bin")
    with pytest.raises(PolicyViolation, match="OTRO archivo"):
        w.open(never, every, out="no.bin", tokens=[issued])                   # una ficha ya emitida NO sirve para otro archivo del mismo candado
    assert w.open(already, [w.part(already, n) for n in ("bea", "carla", "eva")], tokens=[issued])[0] == DATA   # límite declarado: la emitida sigue valiendo


def test_a_token_carries_a_per_file_key_never_the_master(w):
    lock = qsello.Lock.generate("plazo")
    f, g = w.seal(DATA, "uno", locks=[lock]), w.seal(DATA, "dos", locks=[lock])
    tf, tg = json.loads(_token(w, f, lock)), json.loads(_token(w, g, lock))
    assert tf["key"] != tg["key"] and base64.b64decode(tf["key"]) != lock.key and tf["id"] == tg["id"]
    forged = dict(tg, key=tf["key"])                                          # la clave de f presentada como ficha de g
    with pytest.raises(AuthenticationFailure, match="compromiso"):
        w.open(g, [w.part(g, n) for n in ("bea", "carla", "eva")], tokens=[json.dumps(forged).encode()])


@pytest.mark.parametrize("change", [{"v": 2}, {"v": True}, {"id": "00" * 16}, {"key": "AAAA"}, {"extra": 1}, {"file": "0" * 64}])
def test_a_malformed_or_foreign_token_is_refused(w, change):
    lock = qsello.Lock.generate("x")
    f = w.seal(DATA, locks=[lock])
    bad = json.dumps(dict(json.loads(_token(w, f, lock)), **change)).encode()
    with pytest.raises(QCEError):
        w.open(f, [w.part(f, n) for n in ("bea", "carla", "eva")], out="no.bin", tokens=[bad])
    assert not (w.tmp / "no.bin").exists()


def test_the_keeper_releases_only_for_an_authorized_request_for_a_file_that_has_this_lock(w):
    lock, other = qsello.Lock.generate("mio"), qsello.Lock.generate("ajeno")
    f, g = w.seal(DATA, "uno", locks=[lock]), w.seal(DATA, "dos", locks=[lock])
    k = _keeper(w, lock)
    k.register(f, w.sender.public_bytes), k.register(g, w.sender.public_bytes)
    with pytest.raises(PolicyViolation, match="no es de este archivo"):
        _keeper(w, other).register(f, w.sender.public_bytes)
    request = w.request(f)
    with pytest.raises(PolicyViolation, match="OTRO archivo"):
        k.release(g, w.sender.public_bytes, request, _proof(w, k, f, request))
    with pytest.raises(MalformedMessage):
        k.release(f, w.sender.public_bytes, b'{"v":4}', bytes(32))
    wrong = guardian.Keeper(qsello.Lock(lock.ident, "mio", os.urandom(32)), w.tmp / "otra-maestra.diario")
    with pytest.raises(AuthenticationFailure, match="no es la que cierra"):
        wrong.register(f, w.sender.public_bytes)
    proof = _proof(w, k, f, request)
    raw = bytearray(f.read_bytes())
    raw[-1] ^= 1
    f.write_bytes(raw)
    with pytest.raises(AuthenticationFailure):
        k.release(f, w.sender.public_bytes, request, proof)                    # tampoco sobre un archivo alterado
    assert k.deliveries() == []


def test_locks_are_strictly_validated_and_never_printed(w):
    lock = qsello.Lock.generate("secreto")
    assert lock.key.hex() not in repr(lock) and repr(lock.key) not in repr(lock) and str(lock).startswith("Lock(")
    for bad in ((b"x" * 15, "a", bytes(32)), (bytes(16), "a", bytes(31)), (bytes(16), "", bytes(32)), (bytes(16), "a" * 65, bytes(32)), (bytes(16), "a\n", bytes(32))):
        with pytest.raises(PolicyViolation):
            qsello.Lock(*bad)
    (w.tmp / "x").write_bytes(b"x")
    twin = qsello.Lock(lock.ident, "otro", os.urandom(32))
    for locks in ([lock, lock], [lock, twin], [qsello.Lock.generate(str(i)) for i in range(5)]):
        with pytest.raises(PolicyViolation):
            qsello.seal(w.tmp / "x", w.tmp / "x.qsel", w.sender, w.groups(), [w.requester.public_bytes], locks=locks)
    assert not (w.tmp / "x.qsel").exists()


# ------------------------------------------------------------------------------------------------ v0.5: caducidad y guardián endurecido (HYP-0010 y HYP-0011)
NOW = 1_900_000_000


class Clock:
    def __init__(self, t=NOW):
        self.t = t

    def __call__(self):
        return self.t


def _setup(w, clock=None):
    clock = clock or Clock()
    lock = qsello.Lock.generate("plazo")
    f = w.seal(DATA, locks=[lock])
    k = _keeper(w, lock, clock=clock)
    k.register(f, w.sender.public_bytes)
    return lock, f, k, clock


def _request_at(w, f, now=NOW, ttl=3600, reason="auditoria"):
    return qsello.request_open(f, w.sender.public_bytes, w.requester, w.opener.public_bytes, reason, ttl, now)


@pytest.mark.parametrize("when,ok", [(NOW - 301, False), (NOW - 300, True), (NOW, True), (NOW + 3600, True), (NOW + 3601, False)])
def test_custodians_and_keeper_honour_the_validity_window_of_a_request(w, when, ok):
    lock, f, k, clock = _setup(w)
    request = _request_at(w, f)
    proof = _proof(w, k, f, request)
    clock.t = when
    actions = (lambda: qsello.contribute(f, w.sender.public_bytes, w.cust["bea"], request, now=when), lambda: k.release(f, w.sender.public_bytes, request, proof))
    for action in actions:
        if ok:
            assert action()
        else:
            with pytest.raises(PolicyViolation, match="CADUCADO|FUTURO"):
                action()
    assert len(k.deliveries()) == int(ok)


def test_requests_cannot_be_made_to_live_longer_than_a_week(w):
    f = w.seal(DATA)
    for ttl in (0, -1, qsello.MAX_TTL + 1):
        with pytest.raises(PolicyViolation):
            _request_at(w, f, ttl=ttl)
    hd = qsello.read_header(f, w.sender.public_bytes)
    for ttl in (0, qsello.MAX_TTL + 1):                                       # un solicitante autorizado que se salta la comprobación al firmar
        with pytest.raises(MalformedMessage, match="caducidad"):
            qsello.contribute(f, w.sender.public_bytes, w.cust["bea"], _signed_request(hd, w.requester, w.opener.public_bytes, "x", NOW, ttl), now=NOW)
    assert qsello.contribute(f, w.sender.public_bytes, w.cust["bea"], _signed_request(hd, w.requester, w.opener.public_bytes, "x", NOW, qsello.MAX_TTL), now=NOW)
    assert qsello.read_request(hd, _request_at(w, f, ttl=qsello.MAX_TTL), now=NOW).expires == NOW + qsello.MAX_TTL


def test_the_system_clock_is_used_when_none_is_given(w):
    f = w.seal(DATA)
    old = qsello.request_open(f, w.sender.public_bytes, w.requester, w.opener.public_bytes, "vieja", 60, int(time.time()) - 3600)
    with pytest.raises(PolicyViolation, match="CADUCADO"):
        qsello.contribute(f, w.sender.public_bytes, w.cust["bea"], old)


def test_one_request_gets_one_token_even_if_its_json_is_rewritten(w):
    _, f, k, _ = _setup(w)
    request = _request_at(w, f)
    proof = _proof(w, k, f, request)
    assert k.release(f, w.sender.public_bytes, request, proof)
    rewritten = json.dumps(json.loads(request), indent=4).encode()             # mismos campos, otros bytes
    assert rewritten != request
    for again in (request, rewritten):
        with pytest.raises(PolicyViolation, match="YA se atendió"):
            k.release(f, w.sender.public_bytes, again, proof)
    fresh = _request_at(w, f)                                                  # una solicitud NUEVA (otro número) sí
    assert k.release(f, w.sender.public_bytes, fresh, _proof(w, k, f, fresh)) and len(k.deliveries()) == 2
    assert k.deliveries()[0]["reason"] == "auditoria" and k.deliveries()[0]["at"] == NOW


def test_breaking_every_signature_is_not_enough_to_get_a_token(w):
    """El atacante «rompe las firmas»: usa las claves privadas del emisor y del solicitante. Falsifica una cabecera con el mismo `sid` y compromiso (para que la
    ficha sirva contra el archivo robado) y firma solicitudes válidas. No tiene el secreto simétrico del alta ni puede registrar el archivo falso."""
    lock, f, k, _ = _setup(w)
    hd = qsello.read_header(f, w.sender.public_bytes)
    attacker = HybridSigPrivateKey.generate()
    obj = json.loads(hd.raw)
    obj["openers"] = [qsello.fingerprint(attacker.public_bytes)]
    raw = json.dumps(obj).encode()
    prefix = qsello.MAGIC + len(raw).to_bytes(4, "big") + raw
    body = b"cuerpo del atacante" + bytes(16)
    digest = hashlib.sha256(prefix).digest()
    forged = w.tmp / "falsificado.qsel"
    forged.write_bytes(prefix + w.sender.sign(prefix, qsello.CTX_HEADER) + body
                       + w.sender.sign(digest + hashlib.sha256(body).digest() + len(body).to_bytes(8, "big"), qsello.CTX_FILE))
    fhd = qsello.read_header(forged, w.sender.public_bytes)                    # para el guardián, la firma es «válida»
    bad_request = _signed_request(fhd, attacker, w.opener.public_bytes, "deme la ficha", NOW)
    with pytest.raises(PolicyViolation, match="NO registrado"):
        k.release(forged, w.sender.public_bytes, bad_request, bytes(32))
    ident = qsello.read_request(hd, _signed_request(hd, w.requester, w.opener.public_bytes, "x", NOW), NOW).ident
    genuine = _signed_request(hd, w.requester, w.opener.public_bytes, "firmada con la clave robada", NOW)   # archivo REAL, firma «rota» del solicitante real
    for proof in (bytes(32), os.urandom(32), guardian.prove(ident, os.urandom(32)), hashlib.sha256(lock.ident).digest()):
        with pytest.raises(AuthenticationFailure, match="prueba simétrica"):
            k.release(f, w.sender.public_bytes, genuine, proof)
    assert k.deliveries() == []


def test_a_proof_is_good_only_for_its_own_request_and_requester(w):
    _, f, k, _ = _setup(w)
    a, b = _request_at(w, f), _request_at(w, f)
    with pytest.raises(AuthenticationFailure):
        k.release(f, w.sender.public_bytes, b, _proof(w, k, f, a))
    other = HybridSigPrivateKey.generate()
    hd = qsello.read_header(f, w.sender.public_bytes)
    secret_of_other = k.enroll(other.public_bytes)
    with pytest.raises(AuthenticationFailure):                                 # dado de alta, pero su secreto no vale para otro
        k.release(f, w.sender.public_bytes, a, guardian.prove(qsello.read_request(hd, a, NOW).ident, secret_of_other))


def test_registration_withdrawal_enrolment_and_revocation(w):
    lock = qsello.Lock.generate("plazo")
    f = w.seal(DATA, locks=[lock])
    k = guardian.Keeper(lock, w.tmp / "g.diario", clock=Clock())
    digest = qsello.read_header(f, w.sender.public_bytes).digest.hex()
    sid = qsello.read_header(f, w.sender.public_bytes).data["sid"]
    request = _request_at(w, f)

    def attempt(match):
        ident = qsello.read_request(qsello.read_header(f, w.sender.public_bytes), request, NOW).ident
        with pytest.raises(PolicyViolation, match=match):
            k.release(f, w.sender.public_bytes, request, guardian.prove(ident, k.requester_secret(qsello.fingerprint(w.requester.public_bytes))))
    attempt("NO registrado")
    with pytest.raises(PolicyViolation, match="no está registrado"):
        k.withdraw(digest, sid)
    assert k.register(f, w.sender.public_bytes) == digest
    with pytest.raises(PolicyViolation, match="ya está registrado"):
        k.register(f, w.sender.public_bytes)
    attempt("sin alta")
    with pytest.raises(PolicyViolation, match="no está de alta"):
        k.revoke(w.requester.public_bytes)
    secret = k.enroll(w.requester.public_bytes)
    assert len(secret) == 32 and secret != lock.key and secret.hex() not in k.journal.path.read_text()     # el diario no guarda secretos
    with pytest.raises(PolicyViolation, match="ya está dado de alta"):
        k.enroll(w.requester.public_bytes)
    k.revoke(w.requester.public_bytes)
    attempt("sin alta")
    with pytest.raises(PolicyViolation, match="BAJA"):
        k.enroll(w.requester.public_bytes)
    k.withdraw(digest, sid)
    attempt("NO registrado")
    with pytest.raises(PolicyViolation, match="RETIRADO"):
        k.register(f, w.sender.public_bytes)
    text = k.journal.path.read_text()
    assert lock.key.hex() not in text and k.journal.path.stat().st_mode & 0o777 == 0o600


def _journal_with_a_delivery(w):
    lock, f, k, clock = _setup(w)
    request = _request_at(w, f)
    k.release(f, w.sender.public_bytes, request, _proof(w, k, f, request))
    return lock, f, k, request


@pytest.mark.parametrize("damage", [
    lambda L: L[1:], lambda L: [L[0], L[2]], lambda L: [L[1], L[0], L[2]], lambda L: L + [L[-1]], lambda L: [L[0], L[1].replace("register", "withdraw"), L[2]],
    lambda L: [L[0].replace('"n":0', '"n":9'), *L[1:]], lambda L: [*L, "{}\n"], lambda L: [*L, "no es json\n"], lambda L: [*L[:-1], L[-1][:-5]],
    lambda L: [*L[:-1], L[-1].rstrip("\n")], lambda L: [L[0].replace('{"data"', '{"extra":1,"data"'), *L[1:]], lambda L: [*L, "[1]\n"],
])
def test_any_change_inside_the_journal_stops_the_keeper(w, damage):
    _, f, k, request = _journal_with_a_delivery(w)
    lines = k.journal.path.read_text().splitlines(keepends=True)
    assert len(lines) == 3
    k.journal.path.write_text("".join(damage(lines)))
    with pytest.raises(IntegrityError):
        k.deliveries()
    with pytest.raises(IntegrityError):
        k.enroll(HybridSigPrivateKey.generate().public_bytes)                  # y no escribe sobre un diario roto


def test_the_journal_of_another_lock_is_refused(w):
    _, _, k, _ = _journal_with_a_delivery(w)
    with pytest.raises(IntegrityError):
        guardian.Keeper(qsello.Lock.generate("otro"), k.journal.path).journal.head()
    k.journal.path.write_bytes(b"\xff\xfe")
    with pytest.raises(IntegrityError, match="no se puede leer"):
        k.journal.head()


def test_cutting_the_tail_is_only_detected_with_a_pinned_head(w):
    lock, f, k, request = _journal_with_a_delivery(w)
    pin = k.journal.head()
    assert pin[0] == 3
    lines = k.journal.path.read_text().splitlines(keepends=True)
    k.journal.path.write_text("".join(lines[:2]))                                      # se borra la entrega
    assert guardian.Keeper(lock, k.journal.path, clock=Clock()).journal.head()[0] == 2         # LÍMITE declarado: sin ancla no se nota (y la solicitud se podría repetir)
    pinned = guardian.Keeper(lock, k.journal.path, clock=Clock(), pinned_head=pin)
    with pytest.raises(IntegrityError, match="cabeza fijada"):
        pinned.release(f, w.sender.public_bytes, request, _proof(w, k, f, request))
    k.journal.path.write_text("".join(lines))
    assert pinned.journal.head() == pin
    k.enroll(HybridSigPrivateKey.generate().public_bytes)
    assert guardian.Keeper(lock, k.journal.path, pinned_head=pin).journal.head()[0] == 4       # un diario que CRECIÓ sigue cumpliendo la cabeza antigua


def test_a_delivery_that_cannot_be_written_is_not_handed_out_and_leaves_no_broken_line(w, monkeypatch):
    _, f, k, _ = _setup(w)
    request = _request_at(w, f)
    proof = _proof(w, k, f, request)
    before = k.journal.path.read_bytes()

    def boom(fd):
        raise OSError("disco lleno")
    monkeypatch.setattr(journal.os, "fsync", boom)
    with pytest.raises(OSError):
        k.release(f, w.sender.public_bytes, request, proof)
    monkeypatch.undo()
    assert k.journal.path.read_bytes() == before
    assert k.release(f, w.sender.public_bytes, request, proof)


def test_two_keepers_racing_deliver_one_request_exactly_once(w, monkeypatch):
    import threading
    real = journal.Journal._load

    def slow_load(self):
        entries = real(self)
        time.sleep(0.05)                                                       # ensancha la ventana entre leer y anotar: sin candado, TODOS verían «no entregada»
        return entries
    monkeypatch.setattr(journal.Journal, "_load", slow_load)
    lock, f, k, _ = _setup(w)
    request = _request_at(w, f)
    proof = _proof(w, k, f, request)
    for _round in range(5):
        k2 = guardian.Keeper(lock, k.journal.path, clock=Clock())
        results, gate = [], threading.Barrier(6)
        request = _request_at(w, f)
        proof = _proof(w, k, f, request)

        def go(keeper=k2, req=request, pr=proof, out=results, start=gate):
            start.wait()
            try:
                out.append(keeper.release(f, w.sender.public_bytes, req, pr))
            except PolicyViolation:
                out.append(None)
        threads = [threading.Thread(target=go) for _ in range(6)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        assert sum(r is not None for r in results) == 1 and len(results) == 6


@pytest.mark.parametrize("body", [{"n": 5, "type": "enroll", "data": {"requester": "0" * 64, "at": 1}}, {"n": 3, "type": "enroll", "data": {"requester": "0" * 64, "at": 1, "extra": 1}},
                                  {"n": 3, "type": "enroll", "data": {"at": 1}}, {"n": 3, "type": "otra", "data": {"at": 1}}, {"n": 3, "type": "enroll", "data": {"requester": "0" * 64}},
                                  {"n": 3, "type": "enroll", "data": {"requester": "0" * 64, "at": "1"}}])
def test_even_a_correctly_authenticated_entry_must_have_the_right_number_and_shape(w, body):
    """Solo quien tiene la maestra puede fabricar estas entradas (p. ej. un programa defectuoso): el guardián las rechaza igualmente."""
    _, _, k, _ = _journal_with_a_delivery(w)
    previous = k.journal.head()[1]
    mac = journal._mac(k.journal._key, b"QSEL3/journal-entry", previous, journal._canonical(body))
    with open(k.journal.path, "ab") as fh:
        fh.write(journal._canonical({**body, "mac": mac.hex()}) + b"\n")
    with pytest.raises(IntegrityError):
        k.journal.head()
