import pytest

from qce.core.errors import AuthenticationFailure, MalformedMessage, PolicyViolation, ReplayDetected
from qce.pqc.hybrid import (KEM_CT_LEN, HybridKemPrivateKey, HybridSigPrivateKey, hybrid_encapsulate,
                            hybrid_verify)
from qce.symmetric.aead import OpeningKey, ReplayWindow, SealingKey


def test_kem_roundtrip_and_seed_restore():
    k = HybridKemPrivateKey.generate()
    ss, ct = hybrid_encapsulate(k.public_bytes)
    assert len(ct) == KEM_CT_LEN and k.decapsulate(ct) == ss
    assert HybridKemPrivateKey.from_seed(k.seed()).decapsulate(ct) == ss


def test_kem_ciphertext_tamper_gives_different_secret_or_error():
    k = HybridKemPrivateKey.generate()
    ss, ct = hybrid_encapsulate(k.public_bytes)
    for pos in (0, 40, KEM_CT_LEN - 1):  # parte X25519 y parte ML-KEM
        bad = bytearray(ct)
        bad[pos] ^= 1
        assert k.decapsulate(bytes(bad)) != ss  # rechazo implícito: nunca devuelve el secreto real


def test_kem_binds_public_key():
    a, b = HybridKemPrivateKey.generate(), HybridKemPrivateKey.generate()
    ss, ct = hybrid_encapsulate(a.public_bytes)
    assert b.decapsulate(ct) != ss


def test_kem_rejects_bad_lengths():
    k = HybridKemPrivateKey.generate()
    with pytest.raises(MalformedMessage):
        k.decapsulate(b"short")
    with pytest.raises(MalformedMessage):
        hybrid_encapsulate(b"short")


def test_signature_requires_both_components_and_context():
    s = HybridSigPrivateKey.generate()
    sig = s.sign(b"msg", b"ctx")
    hybrid_verify(s.public_bytes, b"msg", sig, b"ctx")
    with pytest.raises(AuthenticationFailure):
        hybrid_verify(s.public_bytes, b"msg", sig, b"other")
    with pytest.raises(AuthenticationFailure):
        hybrid_verify(s.public_bytes, b"msg2", sig, b"ctx")
    for pos in (0, 63, 64, len(sig) - 1):  # rompe SOLO Ed25519 o SOLO ML-DSA
        bad = bytearray(sig)
        bad[pos] ^= 1
        with pytest.raises(AuthenticationFailure):
            hybrid_verify(s.public_bytes, b"msg", bytes(bad), b"ctx")
    with pytest.raises(AuthenticationFailure):
        hybrid_verify(s.public_bytes, b"msg", sig[:-1], b"ctx")


def _pair(aead="CHACHA20-POLY1305"):
    key, prefix = b"k" * 32, b"pfx!"
    return SealingKey(aead, key, prefix), OpeningKey(aead, key, prefix)


@pytest.mark.parametrize("aead", ["CHACHA20-POLY1305", "AES-256-GCM"])
def test_aead_roundtrip_tamper_aad(aead):
    s, o = _pair(aead)
    seq, ct = s.seal(b"hola", b"aad")
    with pytest.raises(AuthenticationFailure):
        o.open(seq, ct, b"otro-aad")
    bad = bytearray(ct)
    bad[0] ^= 1
    with pytest.raises(AuthenticationFailure):
        o.open(seq, bytes(bad), b"aad")
    assert o.open(seq, ct, b"aad") == b"hola"  # los fallos no consumieron el número de secuencia


def test_aead_nonce_never_repeats_and_limit_enforced():
    s = SealingKey("CHACHA20-POLY1305", b"k" * 32, b"pfx!", max_records=3)
    seqs = [s.seal(b"x", b"")[0] for _ in range(3)]
    assert seqs == [0, 1, 2]
    with pytest.raises(PolicyViolation):
        s.seal(b"x", b"")


def test_aead_rejects_short_key():
    with pytest.raises(PolicyViolation):
        SealingKey("CHACHA20-POLY1305", b"k" * 16, b"pfx!")


def test_replay_window_semantics():
    w = ReplayWindow(4)
    for seq in (0, 1, 5, 3):
        w.check(seq)
        w.accept(seq)
    for seq in (5, 3, 1):  # repetidos
        with pytest.raises(ReplayDetected):
            w.check(seq)
    with pytest.raises(ReplayDetected):  # 1 ≤ 5-4: fuera de ventana
        w.check(1)
    with pytest.raises(ReplayDetected):
        w.check(-1)
    w.check(2)  # dentro de ventana y no visto: válido (llegada desordenada)
