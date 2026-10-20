"""Regresiones de la SEGUNDA auditoría adversarial independiente (agente aa53f97…, 2026-10-17)."""
import base64
import hashlib
import json
import shutil
import os
import random
import threading
import uuid
from pathlib import Path

import pytest

from qce.core.chainlog import ChainLog, sanitize
from qce.core.errors import IntegrityError, QCEError
from qce.evolve import gates, mutation
from qce.security import approvals
from qce.evolve.workflow import Task, Workflow
from qce.learning.ledger import Incident, Ledger
from qce.pqc.hybrid import HybridSigPrivateKey
from qce.qkd.contract import DeviceAdapter, ErrorCategory, KeyMaterial, KeyReference, KeyState, QKDDeviceError
from qce.recovery import release as rel
from tests.test_audit_findings import mini_project, mk, snap
from tests.test_qkd_adapters import LAB, Clock, attach, build

ROOT = Path(__file__).resolve().parent.parent


# ---- A1: el snapshot está ligado al release_id ----------------------------------------------------------------
def test_edited_snapshot_with_recomputed_file_hash_is_refused(tmp_path):
    (tmp_path / "p").mkdir()
    root = mini_project(tmp_path / "p")
    key = HybridSigPrivateKey.generate()
    m, d = snap(root, key)
    rel.mark_stable(root, m["release_id"], "humano")
    evil = b"def f(x):\n    return True  # puerta trasera\n"
    (d / "src" / "qce" / "m.py").write_bytes(evil)
    mm = json.loads((d / "manifest.json").read_text())
    mm["files"]["qce/m.py"] = hashlib.sha256(evil).hexdigest()  # el atacante recalcula SU hash…
    (d / "manifest.json").write_text(json.dumps(mm))
    with pytest.raises(IntegrityError, match="release_id"):  # …pero el id (firmado) ya no coincide
        rel.rollback(root)


# ---- A2: symlinks y bytecode no se cuelan fuera del hash -----------------------------------------------------------------
def test_symlinks_in_versioned_tree_are_refused(tmp_path):
    root = mini_project(tmp_path)
    ext = tmp_path.parent / (tmp_path.name + "_ext")
    ext.mkdir()
    (ext / "x.py").write_text("X = 1\n")
    (root / "qce" / "sub").symlink_to(ext)
    with pytest.raises(IntegrityError, match="symlink"):
        rel.build_manifest(root, "1", {}, [], {})


def test_planted_pyc_is_purged_before_tests_run(tmp_path):
    root = mini_project(tmp_path)
    cache = root / "qce" / "__pycache__"
    cache.mkdir()
    (cache / "m.cpython-314.pyc").write_bytes(b"basura")
    gates._purge_bytecode(root)
    assert not cache.exists()


# ---- A3: la reversión no escribe a través de symlinks --------------------------------------------------------------------
def test_rollback_refuses_symlink_targets_that_resolve_into_protected_files(tmp_path):
    (tmp_path / "p").mkdir()
    root = mini_project(tmp_path / "p")
    (root / "learning").mkdir()
    (root / "learning" / "incidents.jsonl").write_text("EVIDENCE\n")
    key = HybridSigPrivateKey.generate()
    m, d = snap(root, key)
    rel.mark_stable(root, m["release_id"], "humano")
    (root / "qce" / "link.py").symlink_to(root / "learning" / "incidents.jsonl")
    mm = json.loads((d / "manifest.json").read_text())
    h = hashlib.sha256(b"PWNED\n").hexdigest()
    (d / "src" / "qce").mkdir(exist_ok=True)
    (d / "src" / "qce" / "link.py").write_text("PWNED\n")
    mm["files"]["qce/link.py"] = h
    mm["release_id"] = hashlib.sha256(json.dumps(mm["files"], sort_keys=True).encode()).hexdigest()[:16]
    with pytest.raises(IntegrityError):  # aunque se rehaga manifiesto e id, el destino es un symlink
        (d / "manifest.json").write_text(json.dumps(mm))
        rel.rollback(root)
    assert (root / "learning" / "incidents.jsonl").read_text() == "EVIDENCE\n"


# ---- A4: el estado inicial no lo decide quien crea la tarea --------------------------------------------------------------------
def test_task_cannot_be_born_in_a_terminal_state_or_with_a_forged_history(tmp_path):
    wf = Workflow(tmp_path / "t.jsonl")
    t = mk()
    t.final_state, t.implementer_id, t.blocking_findings, t.resume_to = "RELEASE_APPROVED", "x", ["F"], "VERIFIED"
    wf.create(t)
    assert wf.state("T1") == "CREATED" and wf.get("T1")["blocking_findings"] == [] and wf.get("T1")["implementer_id"] == ""


def test_structural_ids_cannot_be_secret_looking_hex(tmp_path):
    wf = Workflow(tmp_path / "t.jsonl")
    with pytest.raises(QCEError):
        wf.create(mk(uuid.uuid4().hex))  # el redactor lo destruiría y dos tareas colisionarían
    Ledger(tmp_path / "i.jsonl")
    with pytest.raises(QCEError):
        Ledger(tmp_path / "i.jsonl").open(Incident(uuid.uuid4().hex, "v", "m", "s"))


# ---- A5: umbrales corruptos cierran la puerta, no la anulan -----------------------------------------------------------------------
@pytest.mark.parametrize("bad", [float("nan"), float("inf"), -1, "10", True, None])
def test_non_finite_or_wrongly_typed_thresholds_block_instead_of_disabling_gates(tmp_path, bad):
    root = mini_project(tmp_path)
    cfg = json.loads((root / "gates.json").read_text())
    cfg["min_tests"] = bad
    (root / "gates.json").write_text(json.dumps(cfg))
    rep = gates.evaluate(root, version="t", run_mutation=False, run_dep_audit=False)
    assert rep["state"] == "BLOCKED" and "inválido" in rep["gates"][0]["detail"]


def test_nan_cannot_enter_the_recorded_baseline(tmp_path):
    h = ChainLog(tmp_path / "h.jsonl")
    h.append({"thresholds": {"min_tests": float("nan"), "min_mutants": 5}})
    h.append({"thresholds": {"min_tests": 7}})
    b = gates.strictest_baseline(h)
    assert b["min_tests"] == 7 and b["min_mutants"] == 5


# ---- A6/B7: no se borra la prueba de regresión ni se rebaja la severidad ---------------------------------------------------------
def test_regression_test_of_a_resolved_incident_cannot_be_erased(tmp_path):
    root = mini_project(tmp_path)
    L = Ledger(root / "learning" / "incidents.jsonl")
    L.open(Incident("INC-1", "v", "m", "s", severity="alta", reproduction_test="tests/test_m.py::test_f"))
    L.update("INC-1", status="resuelto", tests_run=["x"])
    with pytest.raises(QCEError):
        L.update("INC-1", reproduction_test="")
    with pytest.raises(QCEError, match="severidad"):
        L.update("INC-1", severity="baja")
    L.update("INC-1", severity="baja", approver="darwin")


def test_g4_flags_resolved_incident_without_any_test(tmp_path):
    root = mini_project(tmp_path)
    log = ChainLog(root / "learning" / "incidents.jsonl")
    log.append({"incident_id": "INC-9", "status": "resuelto", "severity": "critica", "reproduction_test": ""})  # inyectado a mano
    rep = gates.evaluate(root, version="t", run_mutation=False, run_dep_audit=False)
    g4 = next(g for g in rep["gates"] if g["gate"].startswith("G4"))
    assert g4["status"] == "fail" and "INC-9" in g4["evidence"]["regressed"]


# ---- A7/B4/B5: firmas y registro ---------------------------------------------------------------------------------------------------------
def test_case_or_unicode_variants_of_a_signer_cannot_overwrite_a_veto(tmp_path):
    a, b = HybridSigPrivateKey.generate(), HybridSigPrivateKey.generate()
    approvals.register(tmp_path, "reviewer", "alice", a.public_bytes)
    with pytest.raises(QCEError, match="ambigua"):
        approvals.register(tmp_path, "reviewer", "ALICE", b.public_bytes)
    approvals.sign_statement(tmp_path, a, "reviewer", "alice", "R", "reject")
    approvals.sign_statement(tmp_path, a, "reviewer", "alice", "R", "accept")  # el accept NO pisa el reject del mismo firmante
    assert approvals.has_valid_veto(tmp_path, "R", "reviewer") == ["alice"]
    assert approvals.valid_statements(tmp_path, "R", "reviewer") == []


def test_role_change_for_an_existing_identity_is_refused_and_junk_files_are_ignored(tmp_path):
    k = HybridSigPrivateKey.generate()
    approvals.register(tmp_path, "reviewer", "ana", k.public_bytes)
    with pytest.raises(QCEError, match="rol"):
        approvals.register(tmp_path, "approver", "ana", k.public_bytes)
    approvals.sign_statement(tmp_path, k, "reviewer", "ana", "R", "accept")
    (tmp_path / "reviews" / "R.reviewer.junk.json").write_text("{}")
    (tmp_path / "reviews" / "R.reviewer.junk2.json").write_text("no es json")
    assert approvals.valid_statements(tmp_path, "R", "reviewer") == ["ana"]  # antes: KeyError rompía G5/G6


# ---- B1/B2: concurrencia e identidad del implementador ----------------------------------------------------------------------------------
def test_transition_detects_a_log_change_between_validation_and_write(tmp_path, monkeypatch):
    wf = Workflow(tmp_path / "t.jsonl")
    wf.create(mk(risk=2))
    wf.transition("T1", "ANALYZED", "ARCHITECT", "a")
    real = wf._tasks

    def racing():
        out = real()
        wf.log.append({"kind": "noop"})  # otro proceso escribe justo después de validar
        return out
    monkeypatch.setattr(wf, "_tasks", racing)
    with pytest.raises(IntegrityError, match="cambió"):
        wf.transition("T1", "APPROVED_FOR_IMPLEMENTATION", "ARCHITECT", "a")


def test_independence_ignores_case_whitespace_and_remembers_every_implementer(tmp_path):
    wf = Workflow(tmp_path / "t.jsonl")
    wf.create(mk(risk=2))
    wf.transition("T1", "ANALYZED", "ARCHITECT", "x")
    wf.transition("T1", "APPROVED_FOR_IMPLEMENTATION", "ARCHITECT", "x")
    wf.transition("T1", "IMPLEMENTED", "IMPLEMENTER", "alice")
    wf.transition("T1", "REVIEW_REQUIRED", "VERIFIER", "v")
    wf.transition("T1", "IMPLEMENTED", "IMPLEMENTER", "bob")  # otro "reimplementa": alice sigue siendo autora
    wf.transition("T1", "TESTING", "VERIFIER", "v")
    for who in ("alice", "Alice ", "ALICE", "bob"):
        with pytest.raises(QCEError, match="independencia"):
            wf.transition("T1", "INDEPENDENT_REVIEW", "VERIFIER", who, ["run:1"])
    wf.transition("T1", "INDEPENDENT_REVIEW", "VERIFIER", "carol", ["run:1"])


# ---- M1: el broker no confía en los metadatos del dispositivo ----------------------------------------------------------------------------
class RogueAdapterMixin:
    @staticmethod
    def patch(dev, **overrides):
        real = dev.acquire_key

        def acquire(req):
            ref, mat = real(req)
            for k, v in overrides.items():
                setattr(ref, k, v)
            return ref, mat
        dev.acquire_key = acquire


def test_broker_ignores_device_declared_link_state_and_unbounded_expiry(tmp_path):
    broker, dev, link, reg, clock, audit = build(tmp_path, consumers=("sess",))
    attach(broker, dev)
    [kid] = link.generate(1)
    RogueAdapterMixin.patch(dev, peer_or_link_id="L2", state=KeyState.RESERVED, reserved_by="evil", expires_at=1e12, source_device_id="otro")
    broker.refill("L1")
    ref = broker.metadata(kid)
    assert ref.peer_or_link_id == "L1" and ref.state is KeyState.AVAILABLE and ref.reserved_by == "" and ref.source_device_id == "devA"
    assert ref.expires_at <= clock() + broker.policy.max_key_ttl_s
    with pytest.raises(QCEError):
        broker.consume(kid, "evil")  # no puede consumir sin reservar


@pytest.mark.parametrize("field,value", [("expires_at", None), ("expires_at", float("nan")), ("expires_at", float("inf")), ("creation_time", "x"), ("key_reference", "")])
def test_malformed_key_metadata_is_rejected_without_poisoning_other_links(tmp_path, field, value):
    broker, dev, link, *_ = build(tmp_path)
    attach(broker, dev)
    link.generate(1)
    RogueAdapterMixin.patch(dev, **{field: value})
    with pytest.raises(QKDDeviceError) as e:
        broker.refill("L1")
    assert e.value.category is ErrorCategory.INVALID_RESPONSE
    assert broker.status("L1")["keys"] == {}  # status() sigue funcionando (antes: TypeError global)


# ---- M2/M3: ficha y protocolo los fija el alta humano, y attach fallido no contamina ---------------------------------------------------------
def test_spec_declared_by_the_device_is_ignored_in_favour_of_the_enrolled_one(tmp_path):
    from tests.test_qkd_profiles import rig
    from qce.core.errors import QKDAnomaly
    broker, dev, link = rig(tmp_path, protocol="CV-QKD", spec=(("excess_noise_max", 0.05),), faults=("noise_high",))
    dev.spec = (("excess_noise_max", 1e9),)  # el dispositivo declara una ficha permisiva
    broker.attach("L1", dev)
    link.generate(1)
    with pytest.raises(QKDAnomaly):
        broker.refill("L1")


def test_enrolled_protocol_cannot_be_changed_by_the_device(tmp_path):
    from tests.test_qkd_profiles import rig
    broker, dev, link = rig(tmp_path, protocol="MDI-QKD")
    dev.protocol = "BB84"  # intenta presentarse con otro perfil
    with pytest.raises(QKDDeviceError) as e:
        broker.attach("L1", dev)
    assert e.value.category is ErrorCategory.DEVICE_UNTRUSTED


def test_failed_attach_does_not_overwrite_an_existing_links_profile(tmp_path):
    from tests.test_qkd_profiles import rig
    from qce.core.errors import QKDAnomaly
    broker, dev, link = rig(tmp_path, protocol="CV-QKD", spec=(("excess_noise_max", 0.05),), faults=("noise_high",))
    broker.attach("L1", dev)
    ghost = type(dev)("ghost", link, protocol="CV-QKD", spec=(("excess_noise_max", 1e9),))
    ghost.initialize({"registry": broker.registry})
    with pytest.raises(QKDDeviceError):
        broker.attach("L1", ghost)  # no está dado de alta
    link.generate(1)
    with pytest.raises(QKDAnomaly):  # el perfil original sigue vigente
        broker.refill("L1")


def test_non_dict_witnesses_give_a_typed_error(tmp_path):
    broker, dev, link, *_ = build(tmp_path)
    attach(broker, dev)
    link.generate(1)
    good = dev.get_key_service_status
    dev.get_key_service_status = lambda key_id=None: {**good(key_id), "witnesses": ["no", "dict"]}
    with pytest.raises(QKDDeviceError) as e:
        broker.refill("L1")
    assert e.value.category is ErrorCategory.INVALID_RESPONSE


# ---- M4: el arnés de mutación no puede dar un resultado vacío -------------------------------------------------------------------------------------
def test_mutation_only_unknown_names_fail_and_missing_canary_is_reported(tmp_path, monkeypatch):
    root = mini_project(tmp_path)
    with pytest.raises(RuntimeError, match="desconocidos"):
        mutation.run_mutants(root, only=["x"])
    monkeypatch.setattr(mutation, "MUTANTS", [mutation.Mutant("real", "qce/m.py", (("return True", "return False"),), "g")])
    assert mutation.run_mutants(root)["canary_ok"] is False  # sin canario: no es fiable y G3 lo exige


def test_g3_requires_canary_minimum_mutants_and_bounded_equivalents(tmp_path, monkeypatch):
    root = mini_project(tmp_path)
    cfg = json.loads((root / "gates.json").read_text())
    cfg.update(min_mutants=5)
    (root / "gates.json").write_text(json.dumps(cfg))
    monkeypatch.setattr(mutation, "MUTANTS", [mutation.Mutant("real", "qce/m.py", (("return True", "return False"),), "g")])
    rep = gates.evaluate(root, version="t", run_mutation=True, run_dep_audit=False)
    g3 = next(g for g in rep["gates"] if g["gate"].startswith("G3"))
    assert g3["status"] in ("fail", "blocked") and ("canario" in g3["detail"] or "mutantes puntuables" in g3["detail"])


# ---- M5: redactor de secretos --------------------------------------------------------------------------------------------------------------------------
def _leaks(make, n=400):
    leaked = 0
    for _ in range(n):
        secret = make()
        out = json.dumps(sanitize({"nota": f"valor {secret} fin"}))
        leaked += secret in out
    return leaked / n


def test_sanitize_leak_rate_on_realistic_secret_formats_is_below_one_percent():
    rnd = random.Random(7)
    alnum = "abcdefghijklmnopqrstuvwxyz0123456789"
    formats = {
        "b64-16B": lambda: base64.b64encode(os.urandom(16)).decode().rstrip("="),
        "b64-24B": lambda: base64.b64encode(os.urandom(24)).decode(),
        "b64-32B": lambda: base64.b64encode(os.urandom(32)).decode(),
        "b64url-32B": lambda: base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("="),
        "hex-16B": lambda: os.urandom(16).hex(),
        "hex-32B": lambda: os.urandom(32).hex(),
        "hex-colon": lambda: ":".join(f"{b:02x}" for b in os.urandom(16)),
        "sk_live": lambda: "sk_live_" + "".join(rnd.choice(alnum) for _ in range(24)),
        "alnum-lower-40": lambda: "".join(rnd.choice(alnum) for _ in range(40)),
        "ghp": lambda: "ghp_" + "".join(rnd.choice(alnum + alnum.upper()) for _ in range(36)),
        "jwt": lambda: "eyJhbGciOiJIUzI1NiJ9." + base64.urlsafe_b64encode(os.urandom(30)).decode().rstrip("=") + "." + base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("="),
    }
    report = {name: _leaks(f) for name, f in formats.items()}
    assert max(report.values()) < 0.01, report


def test_sanitize_by_key_name_and_bearer_and_structural_ids():
    out = sanitize({"password": "hunter2", "token": "abc123def456", "x": "Authorization: Bearer abcdefgh12345678", "task_id": "T-12", "note": "texto normal"})
    dump = json.dumps(out)
    assert "hunter2" not in dump and "abc123def456" not in dump and "abcdefgh12345678" not in dump
    assert out["task_id"] == "T-12" and out["note"] == "texto normal"


# ---- cierre de supervivientes de la mutación de ronda 2 ----------------------------------------------------------------------------------------
def test_rollback_refuses_symlink_even_when_it_points_to_another_allowed_file(tmp_path):
    (tmp_path / "p").mkdir()
    root = mini_project(tmp_path / "p")
    key = HybridSigPrivateKey.generate()
    m, d = snap(root, key)
    (root / "qce" / "alias.py").symlink_to(root / "qce" / "m.py")  # destino real PERMITIDO: solo la regla de symlinks lo frena
    # snapshot coherente (id = hash de su contenido) y firmado, como lo produciría alguien con la clave de aprobación
    mm = json.loads((d / "manifest.json").read_text())
    body = b"X = 'sobrescrito'\n"
    mm["files"]["qce/alias.py"] = hashlib.sha256(body).hexdigest()
    new_id = hashlib.sha256(json.dumps(mm["files"], sort_keys=True).encode()).hexdigest()[:16]
    mm["release_id"], mm["sequence"] = new_id, 99
    d2 = root / "releases" / new_id
    shutil.copytree(d, d2)
    (d2 / "src" / "qce" / "alias.py").write_bytes(body)
    (d2 / "manifest.json").write_text(json.dumps(mm))
    approvals.sign_statement(root, key, "approver", "humano", new_id, "accept")
    rel.mark_stable(root, new_id, "humano")  # este snapshot es "legítimo": el único freno es la regla de symlinks
    original = (root / "qce" / "m.py").read_text()
    with pytest.raises(IntegrityError, match="symlink"):
        rel.rollback(root)
    assert (root / "qce" / "m.py").read_text() == original


def test_gate_test_runner_purges_planted_bytecode(tmp_path):
    root = mini_project(tmp_path)
    cache = root / "qce" / "__pycache__"
    cache.mkdir()
    (cache / "m.cpython-314.pyc").write_bytes(b"pyc plantado")
    gates._run_pytest(root)
    assert not list(cache.glob("*.pyc")) if cache.exists() else True  # y con -B no se regenera


def _g3(root, monkeypatch, mutants, **cfg):
    c = json.loads((root / "gates.json").read_text())
    c.update(cfg)
    (root / "gates.json").write_text(json.dumps(c))
    monkeypatch.setattr(mutation, "MUTANTS", mutants)
    rep = gates.evaluate(root, version="t", run_mutation=True, run_dep_audit=False)
    return next(g for g in rep["gates"] if g["gate"].startswith("G3"))


def test_g3_each_mutation_requirement_is_enforced_on_its_own(tmp_path, monkeypatch):
    real = mutation.Mutant("real", "qce/m.py", (("return True", "return False"),), "g")
    canary = mutation.Mutant("CANARY-noop", "qce/m.py", (("if x in (1, 2):", "if (x in (1, 2)):"),), "g", "canary")
    equiv = mutation.Mutant("equiv", "qce/m.py", (("return False\n", "return False  \n"),), "g", "no cambia nada")
    root = mini_project(tmp_path)
    g = _g3(root, monkeypatch, [real], min_mutants=0)
    assert "canario" in g["detail"]  # (a) sin canario
    g = _g3(root, monkeypatch, [real, canary], min_mutants=5)
    assert "mutantes puntuables" in g["detail"] and "canario" not in g["detail"]  # (b) pocos mutantes
    g = _g3(root, monkeypatch, [real, canary, equiv], min_mutants=0, max_declared_equivalent=0)
    assert "equivalentes" in g["detail"] and "mutantes puntuables" not in g["detail"]  # (c) demasiados equivalentes
    g = _g3(root, monkeypatch, [real, canary], min_mutants=0, max_declared_equivalent=100)
    assert not any(w in g["detail"] for w in ("canario", "puntuables", "equivalentes", "puntuación"))  # con todo en regla no hay queja de mutación


def test_ledger_error_message_for_erasing_the_regression_test_is_explicit(tmp_path):
    L = Ledger(tmp_path / "i.jsonl")
    L.open(Incident("INC-1", "v", "m", "s", reproduction_test="tests/t.py::test_x"))
    with pytest.raises(QCEError, match="vaciar"):
        L.update("INC-1", reproduction_test="")


def test_key_that_arrives_already_expired_is_refused(tmp_path):
    broker, dev, link, *_ = build(tmp_path)
    attach(broker, dev)
    link.generate(1)
    dev.key_ttl_s = 0.0
    with pytest.raises(QKDDeviceError) as e:
        broker.refill("L1")
    assert e.value.category is ErrorCategory.KEY_EXPIRED


def test_sanitize_keeps_readable_text_with_slashes_and_still_redacts_slash_bearing_base64():
    """INC-0017: 'link/estado/caducidad/ficha/protocolo' se redactaba como base64 y destruía el síntoma de un incidente."""
    txt = "el broker confiaba en link/estado/caducidad/ficha/protocolo que declara el dispositivo"
    assert sanitize(txt) == txt
    key = base64.b64encode(bytes(range(200, 232))).decode()  # contiene '/' o '+' pero también mayúsculas/dígitos
    assert key not in sanitize(f"clave {key}")
