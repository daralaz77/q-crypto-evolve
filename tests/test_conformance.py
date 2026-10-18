"""Conformidad modelo-código (paso 6): trazas del código real frente al modelo formal de QCE1 (formal/qce1.spthy)."""
import json
import random
from pathlib import Path

import pytest

from qce.core.policy import Policy
from qce.evolve import conformance as C
from qce.pqc.hybrid import HybridSigPrivateKey

ROOT = Path(__file__).resolve().parent.parent
EXPECTED = ROOT / "formal" / "expected.json"
needs_formal = pytest.mark.skipif(not EXPECTED.exists(), reason="sin carpeta formal/ (p. ej. en el sandbox de mutación)")

IDENT = HybridSigPrivateKey.generate()
POLICY_BOTH = Policy()
QKD = (b"qkd-id-1", b"q" * 32)


def assert_conformant(tr, **kw):
    assert C.check_lemmas(tr, **kw) == [], tr.scenario
    assert C.check_decisions(tr) == [], tr.scenario


@pytest.mark.parametrize("policy,qkd", [
    (POLICY_BOTH, None),
    (Policy(allowed_suites=("QCE1-XMLKEM768-AESGCM",)), None),
    (POLICY_BOTH, QKD),
])
def test_honest_run_is_a_trace_of_the_model(policy, qkd):
    tr, _ = C.run_session(IDENT, policy, {}, qkd=qkd, scenario="honesto")
    assert C.honest_order_ok(tr), [e[0] for e in tr.events]  # el lema `executable` del modelo, sobre el código real
    assert_conformant(tr)
    assert all(d.accepted and d.guard for d in tr.decisions)
    client, server = tr.sessions
    assert server.open(client.seal(b"hola")) == b"hola" and client.open(server.seal(b"ok")) == b"ok"


def test_model_events_use_values_derived_only_from_the_spec():
    tr, _ = C.run_session(IDENT, POLICY_BOTH, {})
    done_c = next(e for e in tr.events if e[0] == "ClientDone")
    done_s = next(e for e in tr.events if e[0] == "ServerDone")
    assert done_c[2] == done_s[2] and done_c[3] == done_s[3]  # mismo transcript y misma clave c→s, derivados con código independiente
    assert done_c[5] == done_s[4] and done_c[6] == done_s[5]  # mismas suites ofrecidas y elegida


def test_systematic_single_byte_tampering_never_breaks_the_model():
    """Cambia el primer, el último y un byte intermedio de cada mensaje: el caso que pilla comparaciones truncadas."""
    _, wire = C.run_session(IDENT, POLICY_BOTH, {})
    rejected = 0
    for pos in (1, 2, 3, 4):
        n = len(wire[pos - 1])
        for where in (0, 1, n // 2, n - 1):
            tr, _ = C.run_session(IDENT, POLICY_BOTH, {pos: ("flip", where)}, scenario=f"flip m{pos}@{where}")
            assert_conformant(tr)
            rejected += tr.sessions is None
    assert rejected >= 12  # casi todas las alteraciones se rechazan; ninguna produce un ClientDone sin ServerDone


def test_random_active_network_attacker_is_always_a_trace_of_the_model():
    rng = random.Random(20261017)
    pool: dict[int, list[bytes]] = {1: [], 2: [], 3: [], 4: []}
    completed = 0
    rejections = {"C2": 0, "S2": 0, "C3": 0}
    for n in range(400):
        plan = C.random_plan(rng, pool)
        qkd = QKD if n % 5 == 0 else None
        tr, wire = C.run_session(IDENT, POLICY_BOTH, plan, qkd=qkd, scenario=f"aleatorio#{n}")
        assert_conformant(tr)
        for i, m in enumerate(wire, 1):
            pool[i].append(m)
        completed += tr.sessions is not None
        for d in tr.decisions:
            rejections[d.step] += (not d.accepted)
    # no vacío: hubo sesiones completas y rechazos en cada paso con guarda
    assert completed >= 80 and all(v >= 3 for v in rejections.values()), (completed, rejections)


def test_impostor_server_with_other_identity_is_rejected_by_the_client():
    tr, _ = C.run_session(IDENT, POLICY_BOTH, {}, server_ident=HybridSigPrivateKey.generate(), scenario="servidor impostor")
    assert [(d.step, d.accepted, d.guard) for d in tr.decisions] == [("C2", False, False)]
    assert not [e for e in tr.events if e[0] == "ClientDone"]


def test_attack_with_revealed_identity_works_and_the_model_allows_it():
    """≈ Ed25519 + ML-DSA rotos: la traza viola el acuerdo, y el modelo lo excusa SOLO porque la identidad se reveló antes."""
    tr = C.attack_ltk_revealed(IDENT, POLICY_BOTH)
    assert tr.sessions is not None  # el ataque funciona contra el código real, como predice el modelo
    assert C.check_lemmas(tr, expect_secrecy=True) == []
    quitada = C.Trace(events=[e for e in tr.events if e[0] != "RevealLTK"], adversary_keys=tr.adversary_keys)
    violations = C.check_lemmas(quitada)
    assert any("acuerdo" in v for v in violations) and any("firma no liga" in v for v in violations)  # sin la revelación sería un ataque


def test_attack_with_leaked_ephemeral_kem_matches_the_models_breakXM_row():
    """≈ X25519 + ML-KEM rotos: el código falla exactamente donde el modelo dice y aguanta donde el modelo dice."""
    tr = C.attack_ephemeral_kem_leaked(IDENT, POLICY_BOTH)
    assert tr.sessions is not None
    violations = C.check_lemmas(tr)
    row = json.loads(EXPECTED.read_text())["configs"]["breakXM"]["verdicts"]
    assert any("acuerdo" in v for v in violations) == (row["injective_agreement"] == "falsified")
    assert any("secreto" in v for v in violations) == (row["secrecy_c2s"] == "falsified")
    assert any("firma no liga" in v for v in violations) == (row["signature_binds_hello"] == "falsified")  # la firma sigue ligando los Hello


@needs_formal
def test_every_lemma_checked_on_traces_exists_in_the_formal_model():
    model = (ROOT / "formal" / "qce1.spthy").read_text()
    for lemma in ("injective_agreement", "no_downgrade", "signature_binds_hello", "executable"):
        assert f"lemma {lemma}:" in model
    for action in ("ClientStart", "ServerStart", "ClientFinishSent", "ServerDone", "ClientDone", "RevealLTK"):
        assert action in model  # los eventos de las trazas son acciones del modelo


def test_code_is_stricter_than_the_model_only_in_documented_ways():
    """Una sola vez por handshake y política de suites: el modelo permite reintentos; el código no (ver docs/QCE1_CONFORMANCE.md)."""
    tr, wire = C.run_session(IDENT, POLICY_BOTH, {3: ("flip", 700)})
    assert any(d.step == "S2" and not d.accepted for d in tr.decisions)
    assert_conformant(tr)
