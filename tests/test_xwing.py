"""X-Wing (draft-connolly-cfrg-xwing-kem-11): vectores del borrador, propiedades del KEM y fallos cerrados.

Los vectores del Apéndice C incluyen `eseed` (aleatoriedad fija de la encapsulación). La biblioteca `cryptography` no permite fijar la aleatoriedad de ML-KEM, así que NO se
reproduce la encapsulación del vector: se comprueban (a) la clave pública derivada de la semilla y (b) la DECAPSULACIÓN del texto cifrado del borrador, que ejercita ML-KEM, X25519
y el combinador contra el secreto publicado. La encapsulación se prueba con ida y vuelta y con una recomputación independiente.
"""
import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import mlkem, x25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from qce.core.errors import AuthenticationFailure, MalformedMessage
from qce.pqc import hybrid, xwing

VECTORS = json.loads((Path(__file__).parent / "vectors" / "xwing_draft11.json").read_text())["vectors"]


def hx(v, k):
    return bytes.fromhex(v[k])


@pytest.mark.parametrize("i", range(len(VECTORS)))
def test_public_key_from_seed_matches_the_draft(i):
    v = VECTORS[i]
    assert hx(v, "sk") == hx(v, "seed")
    assert xwing.XWingPrivateKey(hx(v, "sk")).public_bytes == hx(v, "pk")


@pytest.mark.parametrize("i", range(len(VECTORS)))
def test_decapsulating_the_draft_ciphertext_gives_the_draft_secret(i):
    v = VECTORS[i]
    assert xwing.XWingPrivateKey(hx(v, "sk")).decapsulate(hx(v, "ct")) == hx(v, "ss")


def test_the_vector_set_is_the_expected_one():
    assert len(VECTORS) == 3
    assert all(len(hx(v, "pk")) == xwing.PK_LEN and len(hx(v, "ct")) == xwing.CT_LEN and len(hx(v, "ss")) == xwing.SS_LEN for v in VECTORS)


def test_constants_match_the_draft_encoding_sizes():
    assert xwing.LABEL == b"\\./" + b"/^\\" and len(xwing.LABEL) == 6
    assert (xwing.SEED_LEN, xwing.PK_LEN, xwing.CT_LEN, xwing.SS_LEN) == (32, 1216, 1120, 32)


def test_round_trip_and_fresh_ciphertexts():
    k = xwing.XWingPrivateKey.generate()
    ss1, ct1 = xwing.xwing_encapsulate(k.public_bytes)
    ss2, ct2 = xwing.xwing_encapsulate(k.public_bytes)
    assert k.decapsulate(ct1) == ss1 and k.decapsulate(ct2) == ss2
    assert ct1 != ct2 and ss1 != ss2 and len(ss1) == 32 and len(ct1) == xwing.CT_LEN


def test_encapsulation_matches_an_independent_recomputation_from_the_primitives():
    """Recalcula el secreto solo con las primitivas y la fórmula del borrador (orden ss_M, ss_X, ct_X, pk_X, etiqueta)."""
    seed = bytes(range(32))
    k = xwing.XWingPrivateKey(seed)
    ss, ct = xwing.xwing_encapsulate(k.public_bytes)
    exp = hashlib.shake_256(seed).digest(96)
    m = mlkem.MLKEM768PrivateKey.from_seed_bytes(exp[:64])
    x = x25519.X25519PrivateKey.from_private_bytes(exp[64:96])
    pk_x = x.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ct_m, ct_x = ct[:1088], ct[1088:]
    ss_x = x.exchange(x25519.X25519PublicKey.from_public_bytes(ct_x))
    want = hashlib.sha3_256(m.decapsulate(ct_m) + ss_x + ct_x + pk_x + bytes.fromhex("5c2e2f2f5e5c")).digest()
    assert ss == want
    assert k.public_bytes == m.public_key().public_bytes_raw() + pk_x          # orden ML-KEM ‖ X25519


def test_the_combiner_input_order_is_ss_m_ss_x_ct_x_pk_x_label():
    a, b, c, d = (bytes([i]) * 32 for i in range(1, 5))
    assert xwing._combine(a, b, c, d) == hashlib.sha3_256(a + b + c + d + xwing.LABEL).digest()
    assert xwing._combine(a, b, c, d) != hashlib.sha3_256(xwing.LABEL + a + b + c + d).digest()      # la etiqueta va AL FINAL


def test_a_modified_ml_kem_part_is_implicitly_rejected_with_a_different_secret():
    k = xwing.XWingPrivateKey.generate()
    ss, ct = xwing.xwing_encapsulate(k.public_bytes)
    bad = bytearray(ct)
    bad[5] ^= 1                                                              # dentro de ct_M
    out = k.decapsulate(bytes(bad))                                          # no lanza: rechazo implícito
    assert out != ss and len(out) == 32 and k.decapsulate(bytes(bad)) == out  # determinista


def test_a_modified_x25519_part_changes_the_secret():
    k = xwing.XWingPrivateKey.generate()
    ss, ct = xwing.xwing_encapsulate(k.public_bytes)
    other = x25519.X25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    assert k.decapsulate(ct[:1088] + other) != ss


def test_a_low_order_x25519_point_fails_closed_on_decapsulation_and_encapsulation():
    k = xwing.XWingPrivateKey.generate()
    ss, ct = xwing.xwing_encapsulate(k.public_bytes)
    zero_point = bytes(32)
    with pytest.raises(AuthenticationFailure, match="X25519"):
        k.decapsulate(ct[:1088] + zero_point)
    with pytest.raises(AuthenticationFailure, match="X25519"):
        xwing.xwing_encapsulate(k.public_bytes[:1184] + zero_point)


@pytest.mark.parametrize("length", [0, 1, xwing.PK_LEN - 1, xwing.PK_LEN + 1])
def test_encapsulation_rejects_a_public_key_of_the_wrong_length(length):
    with pytest.raises(MalformedMessage, match="longitud"):
        xwing.xwing_encapsulate(bytes(length))


@pytest.mark.parametrize("length", [0, xwing.CT_LEN - 1, xwing.CT_LEN + 1])
def test_decapsulation_rejects_a_ciphertext_of_the_wrong_length(length):
    with pytest.raises(MalformedMessage, match="longitud"):
        xwing.XWingPrivateKey.generate().decapsulate(bytes(length))


@pytest.mark.parametrize("length", [0, 31, 33, 64])
def test_a_seed_of_the_wrong_length_is_rejected(length):
    with pytest.raises(MalformedMessage, match="semilla"):
        xwing.XWingPrivateKey(bytes(length))


def test_an_invalid_ml_kem_encapsulation_key_is_rejected():
    k = xwing.XWingPrivateKey.generate()
    bad = bytearray(k.public_bytes)
    bad[0], bad[1] = 0xFF, bad[1] | 0x0F                                      # coeficiente fuera de rango (≥ q)
    with pytest.raises(MalformedMessage, match="ML-KEM"):
        xwing.xwing_encapsulate(bytes(bad))


def test_destroy_makes_the_key_unusable_and_is_reported():
    k = xwing.XWingPrivateKey.generate()
    ss, ct = xwing.xwing_encapsulate(k.public_bytes)
    assert not k.destroyed and k.seed() == k._seed
    k.destroy()
    assert k.destroyed
    with pytest.raises(AuthenticationFailure, match="descartada"):
        k.decapsulate(ct)
    with pytest.raises(AuthenticationFailure, match="descartada"):
        k.seed()


def test_the_same_seed_gives_the_same_key_and_different_seeds_do_not():
    a, b, c = (xwing.XWingPrivateKey(bytes([n]) * 32) for n in (1, 1, 2))
    assert a.public_bytes == b.public_bytes != c.public_bytes


def test_it_is_not_interchangeable_with_the_project_hybrid_kem():
    """El híbrido propio: X25519 ‖ ML-KEM, HKDF, 1216 bytes. X-Wing: ML-KEM ‖ X25519, SHA3-256, 1216 bytes. Misma longitud, otro formato: no se deben mezclar."""
    h = hybrid.HybridKemPrivateKey.generate()
    assert len(h.public_bytes) == xwing.PK_LEN
    with pytest.raises(MalformedMessage, match="ML-KEM"):                    # la parte «ML-KEM» serían 32 bytes X25519 + resto: no es una clave válida
        xwing.xwing_encapsulate(h.public_bytes)
