"""Ancla docs/QCE1_SPEC.md al código.

La re-derivación usa SOLO las fórmulas y constantes del documento (leídas de su bloque `constants`) y primitivas de `cryptography`
directamente; no importa ninguna función de derivación de qce. Si el código o la especificación se separan, estas pruebas fallan.
"""
import hashlib
import hmac
import re
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from qce.core import encoding
from qce.core.policy import Policy
from qce.pqc import hybrid
from qce.pqc.hybrid import HybridKemPrivateKey, HybridSigPrivateKey
from qce.protocols import session as S

SPEC = (Path(__file__).resolve().parent.parent / "docs" / "QCE1_SPEC.md").read_text()


def constants() -> dict[str, str]:
    block = re.search(r"```constants\n(.*?)```", SPEC, re.S)
    assert block, "falta el bloque `constants` en la especificación"
    out = {}
    for line in block.group(1).splitlines():
        if line.strip():
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out


C = constants()


def test_constants_table_matches_code():
    assert C["VERSION"] == S.VERSION.decode()
    assert (int(C["TAG_CLIENT_HELLO"]), int(C["TAG_SERVER_HELLO"]), int(C["TAG_CLIENT_FINISH"]), int(C["TAG_SERVER_FINISH"]),
            int(C["TAG_RECORD"])) == (S.T_CH, S.T_SH, S.T_CF, S.T_SF, S.T_REC)
    assert C["SIGN_CONTEXT"] == S.CTX_SERVER.decode()
    assert C["KEM_LABEL"] == hybrid._LABEL.decode()
    assert (int(C["KEM_PK_LEN"]), int(C["KEM_CT_LEN"]), int(C["SIG_PK_LEN"]), int(C["SIG_LEN"])) == \
        (hybrid.KEM_PK_LEN, hybrid.KEM_CT_LEN, hybrid.SIG_PK_LEN, hybrid.SIG_LEN)
    assert (int(C["MAX_FIELD"]), int(C["MAX_FIELDS"])) == (encoding.MAX_FIELD, encoding.MAX_FIELDS)
    assert int(C["REPLAY_WINDOW"]) == Policy().replay_window


def test_every_constant_in_the_table_is_used_by_the_independent_rederivation():
    """Evita constantes decorativas: las que no se comprueban ni aquí ni arriba se detectan."""
    used = {"VERSION", "TAG_CLIENT_HELLO", "TAG_SERVER_HELLO", "TAG_CLIENT_FINISH", "TAG_SERVER_FINISH", "TAG_RECORD", "SIGN_CONTEXT",
            "KEM_LABEL", "KEM_PK_LEN", "KEM_CT_LEN", "SIG_PK_LEN", "SIG_LEN", "KEYS_INFO_PREFIX", "KEYS_LEN", "SESSION_ID_LEN",
            "MAX_FIELD", "MAX_FIELDS", "REPLAY_WINDOW"}
    assert set(C) == used


# ---- implementación independiente de lo que dice la especificación -------------------------------------------------
def H(*parts: bytes) -> bytes:  # §3
    h = hashlib.sha256()
    for p in parts:
        h.update(len(p).to_bytes(4, "big") + p)
    return h.digest()


def parse(msg: bytes, tag: int, n: int) -> list[bytes]:  # §5, escrito de nuevo
    assert msg[0] == tag and msg[1] == n
    pos, out = 2, []
    for _ in range(n):
        ln = int.from_bytes(msg[pos:pos + 4], "big")
        pos += 4
        assert ln <= int(C["MAX_FIELD"])
        out.append(msg[pos:pos + ln])
        pos += ln
    assert pos == len(msg), "bytes sobrantes"
    return out


def run_handshake(monkeypatch, policy, qkd=None):
    ident = HybridSigPrivateKey.generate()
    captured = {}
    real = HybridKemPrivateKey.decapsulate

    def spy(self, ct):
        captured["ss"] = real(self, ct)
        return captured["ss"]
    monkeypatch.setattr(HybridKemPrivateKey, "decapsulate", spy)
    c = S.ClientHandshake(ident.public_bytes, policy, qkd=qkd)
    s = S.ServerHandshake(ident, policy, qkd_lookup=(lambda i: qkd[1] if qkd and i == qkd[0] else None))
    m1 = c.start()
    m2 = s.on_client_hello(m1)
    m3 = c.on_server_hello(m2)
    m4, ss_sess = s.on_client_finish(m3)
    cs = c.on_server_finish(m4)
    return ident, (m1, m2, m3, m4), captured["ss"], cs, ss_sess


@pytest.mark.parametrize("suite,aead_cls,qkd", [
    ("QCE1-XMLKEM768-CHACHA", ChaCha20Poly1305, None),
    ("QCE1-XMLKEM768-AESGCM", AESGCM, (b"qkd-id-1", b"q" * 32)),
])
def test_independent_rederivation_matches_a_real_handshake(monkeypatch, suite, aead_cls, qkd):
    ident, (m1, m2, m3, m4), ss, cs, srv = run_handshake(monkeypatch, Policy(allowed_suites=(suite,)), qkd)
    version, nonce_c, suites, qid = parse(m1, int(C["TAG_CLIENT_HELLO"]), 4)
    suite_b, nonce_s, kem_pk, sig = parse(m2, int(C["TAG_SERVER_HELLO"]), 4)
    ct, mac_c = parse(m3, int(C["TAG_CLIENT_FINISH"]), 2)
    (mac_s,) = parse(m4, int(C["TAG_SERVER_FINISH"]), 1)
    assert version.decode() == C["VERSION"] and len(nonce_c) == 32 and len(nonce_s) == 32
    assert suite_b.decode() == suite and qid == (qkd[0] if qkd else b"")
    assert (len(kem_pk), len(ct), len(sig), len(ident.public_bytes)) == \
        (int(C["KEM_PK_LEN"]), int(C["KEM_CT_LEN"]), int(C["SIG_LEN"]), int(C["SIG_PK_LEN"]))

    # §6: firma del servidor, con las dos mitades verificadas por separado
    signed = H(m1, suite_b, nonce_s, kem_pk, hashlib.sha256(ident.public_bytes).digest())
    ctx = C["SIGN_CONTEXT"].encode()
    ed25519.Ed25519PublicKey.from_public_bytes(ident.public_bytes[:32]).verify(sig[:64], ctx + b"\x00" + signed)
    mldsa.MLDSA65PublicKey.from_public_bytes(ident.public_bytes[32:]).verify(sig[64:], signed, ctx)

    # §6/§7: transcript, claves y confirmaciones
    th = H(m1, m2, ct)
    secret = ss + (qkd[1] if qkd else b"")
    keys = HKDF(algorithm=hashes.SHA256(), length=int(C["KEYS_LEN"]), salt=th, info=C["KEYS_INFO_PREFIX"].encode() + th).derive(secret)
    ck = keys[64:96]
    assert mac_c == hmac.new(ck, b"client" + th, hashlib.sha256).digest()
    assert mac_s == hmac.new(ck, b"server" + th + mac_c, hashlib.sha256).digest()
    assert cs.session_id == th[:int(C["SESSION_ID_LEN"])] == srv.session_id

    # §8: registros en los dos sentidos, descifrados con primitivas directas
    for sender, direction, key, prefix in ((cs, b"c", keys[0:32], keys[96:100]), (srv, b"s", keys[32:64], keys[100:104])):
        rec = sender.seal(b"hola poscuantico", b"aad")
        seq_b, body = parse(rec, int(C["TAG_RECORD"]), 2)
        assert len(seq_b) == 8
        pt = aead_cls(key).decrypt(prefix + seq_b, body, th[:16] + direction + b"aad")
        assert pt == b"hola poscuantico"


def test_kem_combiner_matches_spec():
    """§4.1: K = HKDF(ss_m ‖ ss_x, LABEL ‖ ct ‖ pk, 32, sin sal)."""
    k = HybridKemPrivateKey.generate()
    K, ct = hybrid.hybrid_encapsulate(k.public_bytes)
    ss_x = k._x.exchange(x25519.X25519PublicKey.from_public_bytes(ct[:32]))
    ss_m = k._m.decapsulate(ct[32:])
    expected = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=C["KEM_LABEL"].encode() + ct + k.public_bytes).derive(ss_m + ss_x)
    assert K == expected == k.decapsulate(ct)


def test_spec_documents_every_open_question_and_non_goal():
    """La especificación debe seguir diciendo lo incómodo: sin autenticación de cliente y con preguntas abiertas."""
    assert "autenticación del **cliente** (no existe)" in SPEC
    assert len(re.findall(r"^\d+\. \*\*", SPEC.split("## 13.")[1].split("## 14.")[0], re.M)) >= 8
