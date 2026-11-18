"""Ronda 5 de auditoría (2026-11-17): el orden de las promociones a ESTABLE lo FIRMA el aprobador.

Antes `mark_stable` comparaba el campo `sequence` del `manifest.json`, que NO está firmado (el `release_id` solo cubre los archivos). Quien pudiera escribir en
`releases/` subía ese número en un snapshot viejo —ya firmado en su día— y lo presentaba como el más nuevo: regreso a código vulnerable. Ahora el número
de la promoción va DENTRO de la firma del aprobador (`qce sign --sequence N`) y es lo único que se compara.
"""
import json

import pytest

from qce.core.errors import IntegrityError, QCEError
from qce.evolve import ceremony
from qce.pqc.hybrid import HybridSigPrivateKey
from qce.recovery import release as rel
from qce.security import approvals

from tests.test_audit_findings import mini_project, snap


@pytest.fixture
def two(tmp_path):
    """Un proyecto con dos snapshots firmados (el viejo con secuencia 1, el nuevo con 2) y el nuevo ya ESTABLE."""
    (tmp_path / "p").mkdir()
    root = mini_project(tmp_path / "p")
    key = HybridSigPrivateKey.generate()
    m1, d1 = snap(root, key, sequence=1)
    (root / "qce" / "m.py").write_text("def f(x):\n    return True\n")
    m2, d2 = snap(root, key, sequence=2)
    rel.mark_stable(root, m2["release_id"], "humano")
    return root, key, m1, d1, m2


def _stable(root):
    return json.loads((root / "releases" / "STABLE").read_text())["release_id"]


def test_editing_the_manifest_sequence_no_longer_helps_to_downgrade(two):
    root, _key, m1, d1, m2 = two
    mm = json.loads((d1 / "manifest.json").read_text())
    mm["sequence"] = 999                                                    # lo que antes bastaba para presentar el snapshot viejo como el más nuevo
    (d1 / "manifest.json").write_text(json.dumps(mm))
    with pytest.raises(QCEError, match="downgrade"):
        rel.mark_stable(root, m1["release_id"], "humano")
    assert _stable(root) == m2["release_id"]


def test_the_manifest_carries_no_unsigned_sequence_number(tmp_path):
    root = mini_project(tmp_path)
    assert "sequence" not in rel.build_manifest(root, "1", {}, [], {})


def test_a_promotion_needs_the_sequence_signed_by_the_approver(tmp_path):
    root = mini_project(tmp_path)
    key = HybridSigPrivateKey.generate()
    m = rel.build_manifest(root, "1", {}, [], {})
    rel.save_release(root, m)
    approvals.register(root, "approver", "humano", key.public_bytes)
    approvals.sign_statement(root, key, "approver", "humano", m["release_id"], "accept")   # firma válida para G6, pero sin número de promoción
    assert approvals.valid_statements(root, m["release_id"], "approver") == ["humano"]
    assert approvals.signed_sequence(root, m["release_id"], "humano") is None
    with pytest.raises(QCEError, match="número de la promoción"):
        rel.mark_stable(root, m["release_id"], "humano")
    assert not (root / "releases" / "STABLE").exists()


def test_the_sequence_must_strictly_grow_and_the_same_release_can_be_marked_again(two):
    root, key, m1, _d1, m2 = two
    rel.mark_stable(root, m2["release_id"], "humano")                       # el mismo snapshot: idempotente
    approvals.sign_statement(root, key, "approver", "humano", m1["release_id"], "accept", sequence=2)   # igual que el estable actual: otro snapshot no puede repetirlo
    with pytest.raises(QCEError, match="downgrade"):
        rel.mark_stable(root, m1["release_id"], "humano")
    approvals.sign_statement(root, key, "approver", "humano", m1["release_id"], "accept", sequence=3)   # el aprobador autoriza una promoción posterior
    rel.mark_stable(root, m1["release_id"], "humano")
    assert _stable(root) == m1["release_id"]


def test_the_signed_sequence_cannot_be_edited_added_or_removed_in_the_statement(two):
    root, key, m1, _d1, m2 = two
    f = next((root / "reviews").glob(f"{m1['release_id']}.approver.*.accept.json"))
    good = json.loads(f.read_text())
    for tampered in (dict(good, sequence=999),                              # subir el número firmado
                     {k: v for k, v in good.items() if k != "sequence"}):   # quitárselo a una firma que lo llevaba
        f.write_text(json.dumps(tampered))
        assert approvals.valid_statements(root, m1["release_id"], "approver") == []
        assert approvals.signed_sequence(root, m1["release_id"], "humano") is None
    legacy = approvals.sign_statement(root, key, "approver", "humano", "legacy1", "accept")           # firma SIN número…
    s = json.loads(legacy.read_text())
    s["sequence"] = 5                                                       # …a la que se le añade uno
    legacy.write_text(json.dumps(s))
    assert approvals.valid_statements(root, "legacy1", "approver") == []


@pytest.mark.parametrize("bad", [0, -1, True, 1.5, "1", None, 2**31, [1]])
def test_a_forged_sequence_field_of_the_wrong_kind_never_makes_a_statement_valid(two, bad):
    root, _key, m1, _d1, _m2 = two
    f = next((root / "reviews").glob(f"{m1['release_id']}.approver.*.accept.json"))
    s = json.loads(f.read_text())
    s["sequence"] = bad
    f.write_text(json.dumps(s))
    if bad is None:
        assert approvals.signed_sequence(root, m1["release_id"], "humano") is None   # "sequence": null equivale a sin número: no coincide con la firma con número
    assert approvals.valid_statements(root, m1["release_id"], "approver") == []


@pytest.mark.parametrize("seq", [0, -1, True, 1.5, "1", 2**31])
def test_signing_refuses_an_invalid_sequence(tmp_path, seq):
    key = HybridSigPrivateKey.generate()
    with pytest.raises(QCEError):
        approvals.sign_statement(tmp_path, key, "approver", "humano", "R", "accept", sequence=seq)
    assert not (tmp_path / "reviews").exists() or list((tmp_path / "reviews").iterdir()) == []


def test_only_an_approver_who_accepts_can_sign_a_sequence(tmp_path):
    key = HybridSigPrivateKey.generate()
    for role, verdict in (("reviewer", "accept"), ("implementer", "accept"), ("approver", "reject")):
        with pytest.raises(QCEError):
            approvals.sign_statement(tmp_path, key, role, "x", "R", verdict, sequence=1)


def test_a_statement_with_a_sequence_still_counts_for_gate_6_and_one_without_it_too(tmp_path):
    key = HybridSigPrivateKey.generate()
    approvals.register(tmp_path, "approver", "humano", key.public_bytes)
    approvals.sign_statement(tmp_path, key, "approver", "humano", "R1", "accept", sequence=4)
    approvals.sign_statement(tmp_path, key, "approver", "humano", "R2", "accept")
    assert approvals.valid_statements(tmp_path, "R1", "approver") == ["humano"]
    assert approvals.valid_statements(tmp_path, "R2", "approver") == ["humano"]
    assert approvals.signed_sequence(tmp_path, "R1", "humano") == 4
    assert approvals.signed_sequence(tmp_path, "R1", "otro") is None        # el número es de ESE firmante
    assert approvals.signed_sequence(tmp_path, "R3", "humano") is None      # y de ESE release


def test_a_reject_still_vetoes_a_signed_sequence(tmp_path):
    key = HybridSigPrivateKey.generate()
    approvals.register(tmp_path, "approver", "humano", key.public_bytes)
    approvals.sign_statement(tmp_path, key, "approver", "humano", "R", "accept", sequence=1)
    approvals.sign_statement(tmp_path, key, "approver", "humano", "R", "reject")
    assert approvals.valid_statements(tmp_path, "R", "approver") == []
    assert approvals.signed_sequence(tmp_path, "R", "humano") is None


def test_an_unreadable_stable_marker_is_refused_instead_of_guessed(two):
    root, _key, m1, _d1, _m2 = two
    (root / "releases" / "STABLE").write_text("{no es json")
    with pytest.raises(IntegrityError, match="STABLE"):
        rel.mark_stable(root, m1["release_id"], "humano")
    (root / "releases" / "STABLE").write_text(json.dumps({"release_id": "x"}))   # sin 'approver'
    with pytest.raises(IntegrityError, match="STABLE"):
        rel.mark_stable(root, m1["release_id"], "humano")


def test_a_previous_stable_without_a_signed_number_counts_as_zero(tmp_path):
    (tmp_path / "p").mkdir()
    root = mini_project(tmp_path / "p")
    key = HybridSigPrivateKey.generate()
    m1, _ = snap(root, key, sequence=1)
    (root / "releases" / "STABLE").write_text(json.dumps({"release_id": m1["release_id"], "approver": "humano"}))
    approvals.sign_statement(root, key, "approver", "humano", m1["release_id"], "accept")   # el estable actual se firmó sin número
    (root / "qce" / "m.py").write_text("def f(x):\n    return True\n")
    m2, _ = snap(root, key, sequence=1)
    rel.mark_stable(root, m2["release_id"], "humano")                       # 1 > 0
    assert _stable(root) == m2["release_id"]


def test_the_ceremony_signs_the_sequence_inside_the_statement(tmp_path):
    root = mini_project(tmp_path / "p") if (tmp_path / "p").mkdir() is None else None
    keys = tmp_path / "keys"
    path, pub = ceremony.new_identity(root, keys, "humano")
    ceremony.register(root, "approver", "humano", pub)
    ceremony.sign(root, path, "approver", "humano", "R9", "accept", "nota", sequence=7)
    assert approvals.signed_sequence(root, "R9", "humano") == 7
    stmt = json.loads(next((root / "reviews").glob("R9.approver.*.accept.json")).read_text())
    assert stmt["sequence"] == 7


def test_the_cli_passes_the_sequence_to_the_signature(tmp_path, monkeypatch):
    from qce import cli
    root = mini_project(tmp_path / "p") if (tmp_path / "p").mkdir() is None else None
    path, pub = ceremony.new_identity(root, tmp_path / "keys", "humano")
    ceremony.register(root, "approver", "humano", pub)
    monkeypatch.setattr(cli, "ROOT", root)
    monkeypatch.setenv("QCE_ALLOW_NONINTERACTIVE_SIGN", "1")
    argv = ["sign", "--role", "approver", "--signer", "humano", "--key", str(path), "--verdict", "accept", "--release-id", "R5", "--sequence", "6"]
    assert cli.main(argv) == 0
    assert approvals.signed_sequence(root, "R5", "humano") == 6
    assert cli.main(argv[:-2]) == 0                                         # sin --sequence: firma sin número (vale para G6, no para promover)
    assert approvals.signed_sequence(root, "R5", "humano") is None


def test_naming_an_approver_without_a_valid_signature_is_refused_for_that_reason(tmp_path):
    root = mini_project(tmp_path)
    key = HybridSigPrivateKey.generate()
    m = rel.build_manifest(root, "1", {}, [], {})
    rel.save_release(root, m)
    approvals.register(root, "approver", "humano", key.public_bytes)
    for who in ("", "humano", "otro"):                                      # sin firma, o firmante inexistente: la razón es la FIRMA, no el número
        with pytest.raises(QCEError, match="declaración firmada y válida"):
            rel.mark_stable(root, m["release_id"], who)
    assert not (root / "releases" / "STABLE").exists()
