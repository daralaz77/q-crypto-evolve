"""Fase 1 de docs/RUTA_ENDURECIMIENTO.md (ítems 1.5 y 1.7; los demás ítems tienen sus propios archivos). Cada control tiene su canario."""
import shutil

import pytest

from qce.core.errors import AuthenticationFailure, IntegrityError, QCEError
from qce.key_management import vault
from qce.key_management.keystore import KeyStore, Purpose
from qce.pqc import hybrid
from qce.pqc.hybrid import HybridSigPrivateKey
from qce.protocols.session import ClientHandshake, ServerHandshake


# ---- 1.7: el descarte de la clave KEM efímera es OBSERVABLE ----
@pytest.fixture(scope="module")
def ident():
    return HybridSigPrivateKey.generate()


@pytest.fixture
def spy_kem(monkeypatch):
    made = []
    real = hybrid.HybridKemPrivateKey.generate.__func__

    def gen(cls, level=hybrid.STANDARD):
        k = real(cls, level)
        made.append(k)
        return k
    monkeypatch.setattr(hybrid.HybridKemPrivateKey, "generate", classmethod(gen))
    return made


def test_ephemeral_kem_key_is_destroyed_after_a_successful_handshake(ident, spy_kem):
    c, s = ClientHandshake(ident.public_bytes), ServerHandshake(ident)
    m3 = c.on_server_hello(s.on_client_hello(c.start()))
    assert spy_kem and not spy_kem[0].destroyed  # antes de terminar, sigue viva
    s.on_client_finish(m3)
    assert spy_kem[0].destroyed
    with pytest.raises(AuthenticationFailure):
        spy_kem[0].decapsulate(bytes(spy_kem[0].level.kem_ct_len))  # ya no puede desencapsular
    with pytest.raises(AuthenticationFailure):
        spy_kem[0].seed()


def test_ephemeral_kem_key_is_destroyed_even_when_the_handshake_fails(ident, spy_kem):
    c, s = ClientHandshake(ident.public_bytes), ServerHandshake(ident)
    m3 = c.on_server_hello(s.on_client_hello(c.start()))
    from qce.core.encoding import pack, unpack
    from qce.protocols.session import T_CF
    ct, mac_c = unpack(m3, T_CF, 2)
    with pytest.raises(QCEError):
        s.on_client_finish(pack(T_CF, [ct, bytes(32)]))  # MAC del cliente falso
    assert spy_kem[0].destroyed


def test_canary_if_destroy_were_skipped_the_observation_would_say_so(ident, spy_kem, monkeypatch):
    monkeypatch.setattr(hybrid.HybridKemPrivateKey, "destroy", lambda self: None)  # el control roto
    c, s = ClientHandshake(ident.public_bytes), ServerHandshake(ident)
    s.on_client_finish(c.on_server_hello(s.on_client_hello(c.start())))
    assert not spy_kem[0].destroyed  # la prueba ANTERIOR fallaría con este código: el control es observable


# ---- 1.5: min_epoch del vault FUERA del vault ----
def make_store(n_ops):
    ks = KeyStore(None, lambda: 1000.0)
    for _ in range(n_ops):
        kid = ks.create(Purpose.ENCRYPT, 3600, secret=b"k" * 32)
        ks.activate(kid)
    return ks


def test_anchor_rejects_a_restored_old_copy_of_the_vault(tmp_path):
    v, anchor = tmp_path / "vault.bin", vault.EpochAnchor(tmp_path / "epoch.json")
    ks = make_store(1)
    vault.save_anchored(ks, v, "frase", anchor, n=2**14)
    old = tmp_path / "old.bin"
    shutil.copy(v, old)  # copia del estado antiguo
    for _ in range(3):  # el estado avanza (p. ej. se revoca una clave)
        kid = ks.create(Purpose.ENCRYPT, 3600, secret=b"x" * 32)
        ks.activate(kid)
    vault.save_anchored(ks, v, "frase", anchor, n=2**14)
    assert anchor.read() == ks.epoch
    shutil.copy(old, v)  # el atacante restaura la copia antigua
    with pytest.raises(IntegrityError, match="restauración de estado antiguo"):  # rechazado POR EL VAULT con el ancla (no solo por advance())
        vault.load_anchored(v, "frase", anchor)
    assert anchor.read() == ks.epoch  # y el ancla no se movió


def test_canary_without_the_external_anchor_the_old_copy_loads_silently(tmp_path):
    v = tmp_path / "vault.bin"
    ks = make_store(1)
    vault.save(ks, v, "frase", n=2**14)
    old = tmp_path / "old.bin"
    shutil.copy(v, old)
    for _ in range(3):
        ks.activate(ks.create(Purpose.ENCRYPT, 3600, secret=b"x" * 32))
    vault.save(ks, v, "frase", n=2**14)
    shutil.copy(old, v)
    assert vault.load(v, "frase").epoch < ks.epoch  # sin ancla: se acepta el epoch antiguo (el problema que cierra el ancla)


def test_anchor_never_goes_backwards_and_a_damaged_anchor_is_not_treated_as_zero(tmp_path):
    a = vault.EpochAnchor(tmp_path / "epoch.json")
    assert a.read() == 0
    a.advance(5)
    with pytest.raises(IntegrityError):
        a.advance(4)
    a.advance(5)
    (tmp_path / "epoch.json").write_text("{no es json")
    with pytest.raises(IntegrityError):
        a.read()  # dañada: NO se asume 0 (permitiría cualquier restauración)
    (tmp_path / "epoch.json").write_text('{"epoch": -3}')
    with pytest.raises(IntegrityError):
        a.read()


def test_anchor_file_is_private_and_written_atomically(tmp_path):
    a = vault.EpochAnchor(tmp_path / "epoch.json")
    a.advance(2)
    assert oct((tmp_path / "epoch.json").stat().st_mode & 0o777) == "0o600"
    assert not list(tmp_path.glob(".epoch-*"))  # sin temporales sobrantes


# ---- 1.6: cada transición del workflow lleva la FIRMA del actor ----
from qce.evolve.workflow import CTX_TRANSITION, Task, Workflow  # noqa: E402


def _task(tid="T1"):
    return Task(tid, "obj", "qce.protocols", "0.1", "TM-1", ["pasa X"], "IMPLEMENTER", ["pytest"], ["tests/test_session.py"], 2, ["reviewer"])


@pytest.fixture(scope="module")
def actors():
    keys = {"arq": HybridSigPrivateKey.generate(), "impl-1": HybridSigPrivateKey.generate()}
    return keys, (lambda actor: keys[actor].public_bytes if actor in keys else None)


def _signed(wf, keys, tid, to, role, who, evidence=None):
    sig = keys[who].sign(wf.signing_payload(tid, to, role, who, evidence), CTX_TRANSITION)
    wf.transition(tid, to, role, who, evidence, signature=sig)


def test_signed_transitions_are_accepted(tmp_path, actors):
    keys, lookup = actors
    wf = Workflow(tmp_path / "t.jsonl", actor_keys=lookup)
    wf.create(_task())
    _signed(wf, keys, "T1", "ANALYZED", "ARCHITECT", "arq")
    assert wf.state("T1") == "ANALYZED" and wf.get("T1")


def test_unsigned_or_unregistered_actor_is_rejected(tmp_path, actors):
    keys, lookup = actors
    wf = Workflow(tmp_path / "t.jsonl", actor_keys=lookup)
    wf.create(_task())
    with pytest.raises(QCEError, match="sin firma"):
        wf.transition("T1", "ANALYZED", "ARCHITECT", "arq")  # sin firma
    with pytest.raises(QCEError, match="sin firma"):
        wf.transition("T1", "ANALYZED", "ARCHITECT", "intruso", signature=b"x" * 10)  # actor no registrado
    assert wf.state("T1") == "CREATED"


def test_canary_a_signature_by_another_actor_or_for_another_transition_is_rejected(tmp_path, actors):
    keys, lookup = actors
    wf = Workflow(tmp_path / "t.jsonl", actor_keys=lookup)
    wf.create(_task())
    forged = keys["impl-1"].sign(wf.signing_payload("T1", "ANALYZED", "ARCHITECT", "arq"), CTX_TRANSITION)  # firma de OTRO actor haciéndose pasar por arq
    with pytest.raises(QCEError):
        wf.transition("T1", "ANALYZED", "ARCHITECT", "arq", signature=forged)
    other = keys["arq"].sign(wf.signing_payload("T1", "ANALYZED", "ARCHITECT", "arq", ["otra:evidencia"]), CTX_TRANSITION)
    with pytest.raises(QCEError):
        wf.transition("T1", "ANALYZED", "ARCHITECT", "arq", signature=other)  # firmada para OTRA evidencia
    assert wf.state("T1") == "CREATED"


def test_a_signature_cannot_be_used_after_the_log_has_advanced(tmp_path, actors):
    """La transición T1 → ANALYZED SIGUE siendo posible; solo cambió la cabeza del registro. Sin la cabeza en lo firmado, la firma vieja se aceptaría."""
    keys, lookup = actors
    wf = Workflow(tmp_path / "t.jsonl", actor_keys=lookup)
    wf.create(_task("T1"))
    sig = keys["arq"].sign(wf.signing_payload("T1", "ANALYZED", "ARCHITECT", "arq"), CTX_TRANSITION)  # firmada sobre la cabeza ACTUAL, sin aplicar
    wf.create(_task("T2"))  # el registro avanza por otro lado
    assert wf.state("T1") == "CREATED"
    with pytest.raises(QCEError, match="firma de la transición inválida"):
        wf.transition("T1", "ANALYZED", "ARCHITECT", "arq", signature=sig)


def test_a_signature_made_for_one_actor_id_cannot_be_presented_as_another_id_sharing_the_key(tmp_path):
    """Dos identificadores que apuntan a la MISMA clave pública (alias): la firma debe ir ligada al actor_id, no solo a la clave."""
    k = HybridSigPrivateKey.generate()
    wf = Workflow(tmp_path / "t.jsonl", actor_keys=lambda a: k.public_bytes if a in ("arq", "arq-alias") else None)
    wf.create(_task())
    sig = k.sign(wf.signing_payload("T1", "ANALYZED", "ARCHITECT", "arq"), CTX_TRANSITION)
    with pytest.raises(QCEError, match="firma de la transición inválida"):
        wf.transition("T1", "ANALYZED", "ARCHITECT", "arq-alias", signature=sig)
    wf.transition("T1", "ANALYZED", "ARCHITECT", "arq", signature=sig)  # con su propio id sí


def test_without_actor_keys_the_historic_unsigned_behaviour_is_unchanged(tmp_path):
    wf = Workflow(tmp_path / "t.jsonl")
    wf.create(_task())
    wf.transition("T1", "ANALYZED", "ARCHITECT", "arq")
    assert wf.state("T1") == "ANALYZED"
