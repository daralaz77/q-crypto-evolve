"""Vectores del sobre sellado: el código y un segundo lector escrito desde la especificación abren los mismos archivos guardados, dan los mismos valores
intermedios y rechazan las mismas alteraciones. Los archivos fijan el FORMATO: si el código cambia una etiqueta o un orden, aquí falla."""
import json
from pathlib import Path

import pytest

from qce.core.errors import QCEError
from qce.pqc.hybrid import LEVELS, HybridSigPrivateKey
from qce.sealed import envelope, keeper, lockshare

from tests import sealed_reader as other
from tests.sealed_vector_cases import CASES, ISSUED, derive, kem_seed_length, plaintext, short

VEC = Path(__file__).parent / "sealed_vectors"
MANIFEST = {m["name"]: m["digests"] for m in json.loads((VEC / "manifest.json").read_text())}


class Vector:
    def __init__(self, case):
        self.c, self.name = case, case["name"]
        self.level, self.suite = LEVELS[case["level"]], envelope.SUITES[case["level"]]
        self.sender = HybridSigPrivateKey.from_seed(derive(self.name, "emisor", 64), self.level)
        self.requester = HybridSigPrivateKey.from_seed(derive(self.name, "solicitante", 64), self.level)
        self.opener_seed = derive(self.name, "apertura", kem_seed_length(case["level"]))
        self.file = VEC / f"{self.name}.qsel"
        self.blob = self.file.read_bytes()
        self.request = (VEC / f"{self.name}.req.msg").read_bytes()
        self.parts = [(VEC / f"{self.name}.{g}-{x}.msg").read_bytes() for g, x in case["quorum"]]
        self.locks = [envelope.Lock(derive(self.name, f"candado-id-{n}", 16), n, derive(self.name, f"candado-{n}", 32)) for n in case["locks"]]
        sid = bytes.fromhex(other.read_file(self.blob, self.sender.public_bytes)["h"]["sid"])
        self.tokens = [json.dumps({"v": 3, "file": other.read_file(self.blob, self.sender.public_bytes)["D"].hex(), "id": k.ident.hex(),
                                   "key": envelope._b64(other.lock_file_key(k.key, sid))}).encode() for k in self.locks]

    def custodian_seed(self, g, x):
        return derive(self.name, f"custodio-{g}-{x}", kem_seed_length(self.c["level"]))


VECTORS = [Vector(c) for c in CASES]
every = pytest.mark.parametrize("v", VECTORS, ids=[v.name for v in VECTORS])


def test_the_vectors_cover_both_levels_both_aeads_several_chunks_and_two_locks():
    assert set(MANIFEST) == {v.name for v in VECTORS}
    assert {v.c["level"] for v in VECTORS} == {"standard", "high"} and {v.c["aead"] for v in VECTORS} == {"AES-256-GCM", "CHACHA20-POLY1305"}
    assert any(v.c["plain_len"] > envelope.CHUNK for v in VECTORS) and any(len(v.locks) == 2 for v in VECTORS)


def test_the_second_reader_does_not_import_the_code_it_checks():
    src = (Path(__file__).parent / "sealed_reader.py").read_text()
    assert not any(line.startswith(("import qce", "from qce", "from .")) for line in src.splitlines())


@every
def test_the_second_reader_opens_the_vector_and_reproduces_every_intermediate_value(v):
    pk, expected = v.sender.public_bytes, MANIFEST[v.name]
    plain, mid = other.open_file(v.blob, pk, v.opener_seed, v.parts, v.tokens)
    assert plain == plaintext(v.c["plain_len"])
    assert short(mid["header_digest"]) == expected["header"] and short(mid["secret"]) == expected["secret"] and short(mid["payload_key"]) == expected["payload_key"]
    assert {f"{g},{x}": short(s) for (g, x), s in sorted(mid["shares"].items())} == expected["shares"]
    assert [short(envelope._unb64(json.loads(t)["key"], 32)) for t in v.tokens] == expected["lock_file_keys"]
    g, x = v.c["quorum"][0]
    _, _, share = other.member_wrap(v.blob, pk, g, x, v.custodian_seed(g, x))
    assert short(share) == expected["shares"][f"{g},{x}"]
    f = other.read_file(v.blob, pk)
    ident = other.read_request(f, v.request, ISSUED)
    assert short(ident) == expected["request_id"]
    with pytest.raises(other.Rejected, match="plazo"):
        other.read_request(f, v.request, ISSUED + 10**7)


@every
def test_the_main_code_opens_the_stored_vector_and_its_stub(v, tmp_path):
    pk = v.sender.public_bytes
    envelope.open_sealed(v.file, tmp_path / "out", pk, v.suite.from_seed(v.opener_seed), v.parts, v.tokens)
    assert (tmp_path / "out").read_bytes() == plaintext(v.c["plain_len"])
    stub = VEC / f"{v.name}.stub"
    assert envelope.make_stub(v.file, pk) == stub.read_bytes()
    from_stub, full = other.read_file(stub.read_bytes(), pk), other.read_file(v.blob, pk)
    assert from_stub["D"] == full["D"] and from_stub["body_hash"] == full["body_hash"] and from_stub["body"] is None
    with pytest.raises(other.Rejected, match="resguardo"):
        other.open_file(stub.read_bytes(), pk, v.opener_seed, v.parts, v.tokens)
    g, x = v.c["quorum"][0]
    assert envelope.contribute(stub, pk, v.suite.from_seed(v.custodian_seed(g, x)), v.request, now=ISSUED)


@every
def test_a_fresh_contribution_and_a_fresh_token_are_accepted_by_the_second_reader(v, tmp_path):
    pk = v.sender.public_bytes
    parts = [envelope.contribute(v.file, pk, v.suite.from_seed(v.custodian_seed(g, x)), v.request, now=ISSUED) for g, x in v.c["quorum"]]
    ident = envelope.read_request(envelope.read_header(v.file, pk), v.request, ISSUED).ident
    assert short(ident) == MANIFEST[v.name]["request_id"]                      # el identificador del código es el publicado (no depende solo del número)
    tokens = []
    for lock in v.locks:
        k = keeper.Keeper(lock, tmp_path / lock.label, clock=lambda: ISSUED)
        k.register(v.file, pk)
        shared = k.enroll(v.requester.public_bytes)
        theirs, proof = other.keeper_proof(lock.key, lock.ident, bytes.fromhex(envelope.fingerprint(v.requester.public_bytes)), ident)
        assert theirs == shared and keeper.prove(ident, shared) == proof   # la prueba simétrica, reproducida desde la especificación
        tokens.append(k.release(v.file, pk, v.request, proof))
    assert other.open_file(v.blob, pk, v.opener_seed, parts, tokens)[0] == plaintext(v.c["plain_len"])


def test_both_agree_on_how_a_split_master_is_rebuilt():
    lock = VECTORS[-1].locks[0]
    parts = lockshare.split_lock(lock, 2, 3)
    chosen = {p.x: p.share for p in parts[1:]}
    assert other.join_lock(chosen, lock.ident, parts[0].commitments, parts[0].master) == lock.key
    with pytest.raises(other.Rejected, match="parte falsa"):
        other.join_lock({1: parts[0].share, 2: bytes(32)}, lock.ident, parts[0].commitments, parts[0].master)


@every
def test_both_readers_reject_the_same_alterations(v, tmp_path):
    pk, blob = v.sender.public_bytes, v.blob
    opener = v.suite.from_seed(v.opener_seed)
    sig = v.level.sig_len
    n = int.from_bytes(blob[6:10], "big")
    positions = [0, 4, 9, 12, 10 + n - 1, 10 + n, 10 + n + sig, len(blob) - sig - 1, len(blob) - 1]
    cases = [blob[:p] + bytes([blob[p] ^ 1]) + blob[p + 1:] for p in positions] + [blob[:-1], blob + b"\x00"]
    bad = tmp_path / "bad.qsel"
    for i, mutated in enumerate(cases):
        with pytest.raises(Exception) as rejected:
            other.open_file(mutated, pk, v.opener_seed, v.parts, v.tokens)
        assert not isinstance(rejected.value, (AssertionError, NameError, TypeError, AttributeError)), (i, rejected.value)
        bad.write_bytes(mutated)
        with pytest.raises(QCEError):
            envelope.open_sealed(bad, tmp_path / "out", pk, opener, v.parts, v.tokens)
    for missing in range(len(v.parts)):                                       # sin una contribución del quórum, los dos se niegan
        rest = v.parts[:missing] + v.parts[missing + 1:]
        with pytest.raises(other.Rejected, match="quórum"):
            other.open_file(blob, pk, v.opener_seed, rest, v.tokens)
        with pytest.raises(QCEError):
            envelope.open_sealed(v.file, tmp_path / "out", pk, opener, rest, v.tokens)
    for missing in range(len(v.tokens)):                                      # y sin una ficha de candado, también
        rest = v.tokens[:missing] + v.tokens[missing + 1:]
        with pytest.raises(other.Rejected, match="candado"):
            other.open_file(blob, pk, v.opener_seed, v.parts, rest)
        with pytest.raises(QCEError, match="candado"):
            envelope.open_sealed(v.file, tmp_path / "out", pk, opener, v.parts, rest)
    assert not (tmp_path / "out").exists()
