import pytest

from qce.core.errors import QCEError
from qce.evolve.workflow import Task, Workflow


def mk(tid="T1", risk=2, criteria=("pasa X",)):
    return Task(tid, "obj", "qce.protocols", "0.1", "TM-1", list(criteria), "IMPLEMENTER", ["pytest"],
                ["tests/test_session.py"], risk, ["reviewer"])


def advance_to(wf, tid, upto):
    steps = [("ANALYZED", "ARCHITECT", "arq"), ("APPROVED_FOR_IMPLEMENTATION", "ARCHITECT", "arq"),
             ("IMPLEMENTED", "IMPLEMENTER", "impl-1"), ("TESTING", "VERIFIER", "ver-1"),
             ("INDEPENDENT_REVIEW", "VERIFIER", "ver-1"), ("VERIFIED", "VERIFIER", "ver-1"),
             ("RELEASE_REVIEW", "RELEASE-GUARDIAN", "rg-1")]
    for to, role, who in steps:
        ev = ["run:123"] if to in ("INDEPENDENT_REVIEW", "VERIFIED") else None
        wf.transition(tid, to, role, who, ev)
        if to == upto:
            return


def test_full_path_needs_human_for_release(tmp_path):
    wf = Workflow(tmp_path / "t.jsonl", approval_verifier=lambda ref: ref == "T1.json")
    wf.create(mk())
    advance_to(wf, "T1", "RELEASE_REVIEW")
    with pytest.raises(QCEError):
        wf.transition("T1", "RELEASE_APPROVED", "RELEASE-GUARDIAN", "rg-1", ["approval:T1.json"])  # ningún agente aprueba
    with pytest.raises(QCEError):  # una referencia inventada no verifica
        wf.transition("T1", "RELEASE_APPROVED", "HUMAN", "darwin", ["approval:no-existe.json"])
    with pytest.raises(QCEError):
        wf.transition("T1", "RELEASE_APPROVED", "HUMAN", "darwin")  # riesgo ≥2 sin declaración firmada
    wf.transition("T1", "RELEASE_APPROVED", "HUMAN", "darwin", ["approval:T1.json"])
    assert wf.state("T1") == "RELEASE_APPROVED"


def test_cannot_skip_implemented_to_release_approved(tmp_path):
    wf = Workflow(tmp_path / "t.jsonl")
    wf.create(mk())
    advance_to(wf, "T1", "IMPLEMENTED")
    for target in ("RELEASE_APPROVED", "VERIFIED", "RELEASE_REVIEW"):
        with pytest.raises(QCEError):
            wf.transition("T1", target, "HUMAN", "darwin", ["x"])


def test_implementer_cannot_evaluate_own_change(tmp_path):
    wf = Workflow(tmp_path / "t.jsonl")
    wf.create(mk())
    advance_to(wf, "T1", "TESTING")
    with pytest.raises(QCEError):
        wf.transition("T1", "INDEPENDENT_REVIEW", "VERIFIER", "impl-1", ["run:1"])  # misma identidad
    wf.transition("T1", "INDEPENDENT_REVIEW", "VERIFIER", "ver-1", ["run:1"])


def test_blocking_finding_stops_promotion_and_failed_path_rolls_back(tmp_path):
    wf = Workflow(tmp_path / "t.jsonl")
    wf.create(mk())
    advance_to(wf, "T1", "INDEPENDENT_REVIEW")
    with pytest.raises(QCEError):
        wf.transition("T1", "VERIFIED", "VERIFIER", "ver-1", ["run:2"], blocking_findings=["CRIT-1"])
    wf.transition("T1", "FAILED", "VERIFIER", "ver-1", ["run:2"])
    wf.transition("T1", "ROLLED_BACK", "RELEASE-GUARDIAN", "rg-1")
    assert wf.history("T1")[-2:] == ["FAILED", "ROLLED_BACK"]


def test_evidence_required_and_level3_needs_human_approval(tmp_path):
    wf = Workflow(tmp_path / "t.jsonl")
    wf.create(mk("T3", risk=3))
    wf.transition("T3", "ANALYZED", "ARCHITECT", "arq")
    with pytest.raises(QCEError):
        wf.transition("T3", "APPROVED_FOR_IMPLEMENTATION", "ARCHITECT", "arq")
    wf.transition("T3", "APPROVED_FOR_IMPLEMENTATION", "HUMAN", "darwin")
    wf2 = Workflow(tmp_path / "t2.jsonl")
    wf2.create(mk("T4"))
    advance_to(wf2, "T4", "TESTING")
    with pytest.raises(QCEError):
        wf2.transition("T4", "INDEPENDENT_REVIEW", "VERIFIER", "ver-1", [])  # sin evidencia


def test_state_survives_restart_and_tampering_is_detected(tmp_path):
    p = tmp_path / "t.jsonl"
    wf = Workflow(p)
    wf.create(mk())
    wf.transition("T1", "ANALYZED", "ARCHITECT", "arq")
    assert Workflow(p).state("T1") == "ANALYZED"  # estado reconstruido desde el registro
    with pytest.raises(QCEError):
        Workflow(p).create(mk())  # duplicada
    p.write_text(p.read_text().replace("ANALYZED", "VERIFIED"))
    from qce.core.errors import IntegrityError
    with pytest.raises(IntegrityError):
        Workflow(p).log.verify()


def test_invalid_role_and_empty_criteria(tmp_path):
    wf = Workflow(tmp_path / "t.jsonl")
    t = mk()
    t.assigned_role = "ROOT"
    with pytest.raises(QCEError):
        wf.create(t)
    wf.create(mk("T9", criteria=()))
    wf.transition("T9", "ANALYZED", "ARCHITECT", "arq")
    with pytest.raises(QCEError):
        wf.transition("T9", "APPROVED_FOR_IMPLEMENTATION", "ARCHITECT", "arq")
