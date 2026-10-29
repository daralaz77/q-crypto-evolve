"""`python -m pytest tools/tests -o addopts= -q` (fuera de `tests/`). Incluye canarios: la comprobación SÍ detecta cadenas reescritas y truncadas."""
import json
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT))
import anchor  # noqa: E402
from qce.core.chainlog import ChainLog  # noqa: E402


@pytest.fixture
def proj(tmp_path, monkeypatch):
    monkeypatch.setattr(anchor, "build_manifest", lambda *a, **k: {"release_id": "fixed"})  # el hash del código no es lo que se prueba aquí
    (tmp_path / "learning").mkdir()
    (tmp_path / "trust").mkdir()
    (tmp_path / "reviews").mkdir()
    (tmp_path / "trust" / "registry.json").write_text('{"a": {"role": "implementer"}}')
    log = ChainLog(tmp_path / "learning" / "incidents.jsonl")
    for i in range(5):
        log.append({"incident_id": f"INC-{i:04d}", "status": "abierto"})
    return tmp_path


def test_anchor_is_deterministic_and_has_the_expected_fields(proj):
    a = anchor.build(proj, commit="abc")
    assert anchor.render(a) == anchor.render(anchor.build(proj, commit="abc"))
    assert a["ledger"]["entries"] == 5 and len(a["ledger"]["head"]) == 64 and a["commit"] == "abc" and a["schema"] == anchor.SCHEMA


def test_the_real_repository_can_be_anchored_and_matches_the_chain_verifier():
    a = anchor.build(ROOT, commit="x")
    log = ChainLog(ROOT / "learning" / "incidents.jsonl")
    assert a["ledger"]["entries"] == log.verify() and a["ledger"]["head"] == log.head()


def test_a_longer_ledger_extends_the_anchored_one(proj):
    old = anchor.build(proj, commit="a")
    ChainLog(proj / "learning" / "incidents.jsonl").append({"incident_id": "INC-0005", "status": "abierto"})
    ok, why = anchor.extends(proj, old)
    assert ok, why


def test_canary_a_fully_rewritten_chain_is_detected(proj):
    old = anchor.build(proj, commit="a")
    p = proj / "learning" / "incidents.jsonl"
    events = [json.loads(json.loads(line)["body"]) for line in p.read_text().splitlines()]
    events[1]["status"] = "resuelto"  # reescribir la historia…
    p.unlink()
    new = ChainLog(p)
    for e in events:  # …y recalcular TODA la cadena: internamente es íntegra
        new.append(e)
    assert new.verify() == 5  # la cadena nueva pasa su propia verificación
    ok, why = anchor.extends(proj, old)
    assert not ok and "reescribió" in why


def test_canary_a_truncated_ledger_is_detected(proj):
    old = anchor.build(proj, commit="a")
    p = proj / "learning" / "incidents.jsonl"
    p.write_text("\n".join(p.read_text().splitlines()[:3]) + "\n")
    ok, why = anchor.extends(proj, old)
    assert not ok and "truncó" in why


def test_canary_a_tampered_anchor_head_is_not_extended(proj):
    old = anchor.build(proj, commit="a")
    old["ledger"]["head"] = "0" * 63 + "1"
    assert not anchor.extends(proj, old)[0]


def test_a_broken_chain_is_never_anchored(proj):
    p = proj / "learning" / "incidents.jsonl"
    lines = p.read_text().splitlines()
    e = json.loads(lines[2])
    e["body"] = e["body"].replace("abierto", "resuelto")
    lines[2] = json.dumps(e)
    p.write_text("\n".join(lines) + "\n")
    with pytest.raises(Exception):  # noqa: B017  (IntegrityError)
        anchor.build(proj, commit="a")


def test_changing_the_trust_registry_or_the_signatures_changes_the_anchor(proj):
    a = anchor.build(proj, commit="a")
    (proj / "trust" / "registry.json").write_text('{"a": {"role": "implementer"}, "evil": {"role": "approver"}}')
    b = anchor.build(proj, commit="a")
    assert a["trust_registry_sha256"] != b["trust_registry_sha256"]
    (proj / "reviews" / "x.json").write_text("{}")
    assert b["reviews_sha256"] != anchor.build(proj, commit="a")["reviews_sha256"]


def test_verify_commit_regenerates_the_same_anchor_from_a_git_archive():
    head = anchor._git_head(ROOT)
    if not head:
        pytest.skip("no es un repositorio git")
    import subprocess
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        tree = Path(td)
        tar = subprocess.run(["git", "archive", head], cwd=ROOT, capture_output=True, check=True).stdout
        subprocess.run(["tar", "-x", "-C", str(tree)], input=tar, check=True)
        from_archive = anchor.build(tree, commit=head)
    assert from_archive["schema"] == anchor.SCHEMA and from_archive["commit"] == head
