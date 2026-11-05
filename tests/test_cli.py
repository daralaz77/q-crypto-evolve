"""Pruebas de la CLI (`python -m qce`).

Regla de seguridad de estas pruebas: NINGUNA escribe en el repositorio real. Todo comando que escribe (`gates`, `release`, `bench`, `identity`, `sign`)
corre contra un proyecto mínimo en un directorio temporal (`cli.ROOT` se redirige). Los comandos pesados (`test`, `mutate`, `demo`, `formal`, `scan`)
se prueban por su contrato con la CLI —código de salida y salida impresa— sustituyendo la pieza costosa, que ya tiene sus propias pruebas.
"""
import json
import subprocess
import sys
import types
from pathlib import Path

import pytest

from qce import cli
from qce.evolve import ceremony
from qce.learning.ledger import Incident, Ledger
from qce.security import approvals
from tests.test_audit_findings import mini_project

REAL = Path(__file__).resolve().parent.parent


@pytest.fixture
def lab(tmp_path, monkeypatch):
    (tmp_path / "proj").mkdir()
    root = mini_project(tmp_path / "proj")
    monkeypatch.setattr(cli, "ROOT", root)
    return root


def run(argv, capsys):
    rc = cli.main(argv)
    return rc, capsys.readouterr().out


# ---- el analizador de argumentos ----------------------------------------------------------------------------
ARGV = [
    ["test"], ["scan"], ["mutate"], ["gates"], ["gates", "--fast"], ["demo"], ["formal"], ["review-package"],
    ["review-package", "--verify", "x.zip", "--out", "o"], ["supply-chain"], ["supply-chain", "--check"], ["tls-check"], ["tls-check", "--strict"], ["bench"],
    ["release"], ["status"], ["identity", "new", "ana"], ["identity", "new", "ana", "--dir", "/k"],
    ["identity", "register", "--role", "approver", "--identity", "ana", "--pub", "ab"],
    ["sign", "--role", "reviewer", "--signer", "ana", "--key", "k", "--verdict", "accept"],
]


@pytest.mark.parametrize("argv", ARGV, ids=lambda a: " ".join(a))
def test_every_documented_command_parses_and_has_a_handler(argv):
    a = cli._build_parser().parse_args(argv)
    assert a.cmd == argv[0] and a.cmd in cli.COMMANDS


@pytest.mark.parametrize("argv", [
    [], ["no-existe"], ["gates", "--rapido"], ["sign", "--role", "reviewer"],
    ["sign", "--role", "dios", "--signer", "a", "--key", "k", "--verdict", "accept"],
    ["sign", "--role", "reviewer", "--signer", "a", "--key", "k", "--verdict", "quizas"],
    ["identity"], ["identity", "register", "--role", "approver", "--identity", "a"],
    ["identity", "register", "--role", "otro", "--identity", "a", "--pub", "ab"],
], ids=lambda a: " ".join(a) or "(sin comando)")
def test_bad_command_lines_are_refused_with_exit_2(argv):
    with pytest.raises(SystemExit) as e:
        cli._build_parser().parse_args(argv)
    assert e.value.code == 2


def test_main_returns_2_when_the_command_has_no_handler(monkeypatch):
    monkeypatch.setattr(cli, "COMMANDS", {})
    assert cli.main(["status"]) == 2


def test_python_dash_m_qce_is_wired():
    r = subprocess.run([sys.executable, "-m", "qce", "--help"], cwd=REAL, capture_output=True, text=True, timeout=60)
    assert r.returncode == 0 and "Q-Crypto Evolve" in r.stdout and "gates" in r.stdout
    r = subprocess.run([sys.executable, "-m", "qce"], cwd=REAL, capture_output=True, text=True, timeout=60)
    assert r.returncode == 2 and "required" in r.stderr.lower()


# ---- test / scan / mutate ---------------------------------------------------------------------------------------
def test_test_command_runs_pytest_in_the_project_root_and_returns_its_exit_code(lab, monkeypatch, capsys):
    seen = {}
    monkeypatch.setattr(cli.subprocess, "call", lambda args, cwd=None: seen.update(args=args, cwd=cwd) or 5)
    assert cli.main(["test"]) == 5
    assert seen["args"][1:] == ["-m", "pytest"] and seen["cwd"] == lab


@pytest.mark.parametrize("misuse, secrets, deps, expected", [
    ([], [], {"status": "limpia"}, 0),
    (["m"], [], {"status": "limpia"}, 1),
    ([], ["s"], {"status": "limpia"}, 1),
    ([], [], {"status": "vulnerable"}, 1),
    ([], [], {"status": "no_ejecutada"}, 1),     # sin auditoría de dependencias NO es "limpio"
])
def test_scan_exits_nonzero_unless_everything_is_clean(lab, monkeypatch, capsys, misuse, secrets, deps, expected):
    from qce.security import scanners as s
    mk = lambda tag: s.Finding(tag, "a.py", 1, "d", "alta")       # noqa: E731
    monkeypatch.setattr(s, "scan_misuse", lambda root: [mk(t) for t in misuse])
    monkeypatch.setattr(s, "scan_secrets", lambda root: [mk(t) for t in secrets])
    monkeypatch.setattr(s, "audit_dependencies", lambda root: deps)
    rc, out = run(["scan"], capsys)
    data = json.loads(out)
    assert rc == expected and set(data) == {"misuse", "secrets", "dependencies"}
    assert len(data["misuse"]) == len(misuse) and len(data["secrets"]) == len(secrets)


@pytest.mark.parametrize("survivors, expected", [([], 0), (["m1"], 1)])
def test_mutate_fails_when_a_mutant_survives_and_hides_the_noisy_detail(lab, monkeypatch, capsys, survivors, expected):
    from qce.evolve import mutation
    monkeypatch.setattr(mutation, "run_mutants", lambda root: {"survivors": survivors, "score": 1.0, "detail": ["x" * 50]})
    rc, out = run(["mutate"], capsys)
    assert rc == expected and "detail" not in json.loads(out) and json.loads(out)["survivors"] == survivors


# ---- gates -------------------------------------------------------------------------------------------------------------
def fake_report(state):
    return {"state": state, "release_id": "abc123", "metrics": {"tests_passed": 3},
            "gates": [{"gate": "G1-INTEGRIDAD", "status": "pass", "detail": "ok " * 100}]}


@pytest.mark.parametrize("state, expected", [("VERIFIED", 0), ("RELEASE_APPROVED", 0), ("REVIEW_REQUIRED", 1), ("BLOCKED", 1), ("FAILED", 1)])
def test_gates_exit_code_reflects_the_final_state_and_the_report_is_saved(lab, monkeypatch, capsys, state, expected):
    from qce.evolve import gates
    monkeypatch.setattr(gates, "evaluate", lambda root, **kw: fake_report(state))
    rc, out = run(["gates"], capsys)
    assert rc == expected and f"ESTADO: {state}" in out
    assert json.loads((lab / "benchmarks" / "gates_latest.json").read_text())["state"] == state
    assert max(len(line) for line in out.splitlines() if line.startswith("G1")) <= 20 + 1 + 8 + 1 + 150   # el detalle se recorta a 150


@pytest.mark.parametrize("argv, mutation, deps", [(["gates"], True, True), (["gates", "--fast"], False, False)])
def test_fast_flag_skips_mutation_and_dependency_audit(lab, monkeypatch, capsys, argv, mutation, deps):
    from qce.evolve import gates
    seen = {}
    monkeypatch.setattr(gates, "evaluate", lambda root, **kw: seen.update(kw) or fake_report("BLOCKED"))
    cli.main(argv)
    assert seen["run_mutation"] is mutation and seen["run_dep_audit"] is deps and seen["version"] == cli.VERSION


# ---- demo / formal / review-package / supply-chain ------------------------------------------------------------------------
@pytest.mark.parametrize("ok, expected, word", [(True, 0, "COMPLETA"), (False, 1, "CON FALLOS")])
def test_demo_reports_and_returns_according_to_all_ok(lab, monkeypatch, capsys, ok, expected, word):
    from qce.evolve import demo
    monkeypatch.setattr(demo, "run", lambda project, out: {"log": ["[OK ] a"], "all_ok": ok, "checks": [{"ok": True}, {"ok": ok}], "timings_s": {"total": 1}})
    rc, out = run(["demo"], capsys)
    assert rc == expected and word in out and f"{1 + ok}/2" in out


def test_formal_without_tamarin_exits_2_and_says_it_did_not_verify(lab, monkeypatch, capsys):
    from qce.evolve import formal
    monkeypatch.setattr(formal, "available", lambda: False)
    rc, out = run(["formal"], capsys)
    assert rc == 2 and "NO ejecutada" in out


@pytest.mark.parametrize("problems, expected", [([], 0), (["veredicto distinto"], 1)])
def test_formal_with_tamarin_returns_1_on_any_model_problem(lab, monkeypatch, capsys, problems, expected):
    from qce.evolve import formal
    monkeypatch.setattr(formal, "available", lambda: True)
    monkeypatch.setattr(formal, "check_matrix", lambda *a, **k: list(problems))
    monkeypatch.setattr(formal, "check_model_mutants", lambda *a, **k: [])
    rc, out = run(["formal"], capsys)
    assert rc == expected and (problems[0] in out if problems else "conformes" in out)


def test_review_package_builds_and_verifies(lab, monkeypatch, capsys):
    from qce.evolve import review_package as rpk
    monkeypatch.setattr(rpk, "build", lambda root, out: (out / "p.zip", "deadbeef"))
    rc, out = run(["review-package", "--out", "salida"], capsys)
    assert rc == 0 and "deadbeef" in out and "NO está firmado" in out and str(lab / "salida") in out
    monkeypatch.setattr(rpk, "verify", lambda z: [])
    assert run(["review-package", "--verify", "z.zip"], capsys) == (0, "paquete íntegro: todos los archivos coinciden con MANIFEST.sha256\n")
    monkeypatch.setattr(rpk, "verify", lambda z: ["a.py: hash distinto"])
    rc, out = run(["review-package", "--verify", "z.zip"], capsys)
    assert rc == 1 and "a.py: hash distinto" in out


def test_supply_chain_check_generate_and_network_failure(lab, monkeypatch, capsys):
    from qce.evolve import supply_chain as sc
    monkeypatch.setattr(sc, "check", lambda root: [])
    assert run(["supply-chain", "--check"], capsys)[0] == 0
    monkeypatch.setattr(sc, "check", lambda root: ["hash no coincide"])
    rc, out = run(["supply-chain", "--check"], capsys)
    assert rc == 1 and "hash no coincide" in out
    monkeypatch.setattr(sc, "generate", lambda root, v: ["cryptography"])
    rc, out = run(["supply-chain"], capsys)
    assert rc == 0 and "cryptography" in out

    def offline(root, v):
        raise OSError("sin red")
    monkeypatch.setattr(sc, "generate", offline)
    rc, out = run(["supply-chain"], capsys)
    assert rc == 2 and "OSError" in out and "no se pudo generar" in out    # se declara, no se inventa


# ---- tls-check ----------------------------------------------------------------------------------------------------------------
def test_tls_check_real_attestation_in_a_fresh_process():
    r = subprocess.run([sys.executable, "-m", "qce", "tls-check"], cwd=REAL, capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "atestación OK" in r.stdout and "X25519MLKEM768" in r.stdout


def test_tls_check_fails_closed_with_exit_2_when_the_stack_is_not_guaranteed(lab, monkeypatch, capsys):
    import qce.transport

    class Misconfigured(Exception):
        pass

    def refuse():
        raise Misconfigured("la pila TLS no garantiza el grupo híbrido")
    fake = types.SimpleNamespace(TransportMisconfigured=Misconfigured, require_hybrid_only=refuse, HYBRID_GROUP="X25519MLKEM768")
    monkeypatch.setattr(qce.transport, "tls13", fake, raising=False)
    monkeypatch.setitem(sys.modules, "qce.transport.tls13", fake)
    rc, out = run(["tls-check"], capsys)
    assert rc == 2 and "TRANSPORTE NO GARANTIZADO" in out


# ---- bench / release / status --------------------------------------------------------------------------------------------------
def test_bench_writes_its_report_only_in_the_project_root_and_claims_no_security(lab, capsys):
    rc, out = run(["bench"], capsys)
    data = json.loads((lab / "benchmarks" / "bench_latest.json").read_text())
    assert rc == 0 and data == json.loads(out)
    assert {"kem_keygen", "kem_encaps", "kem_decaps", "sig_sign", "sig_verify", "handshake_total"} <= set(data)
    assert all(data[k] > 0 for k in ("kem_keygen", "handshake_total")) and "no sustentan ninguna afirmación de seguridad" in data["nota"]


def test_release_freezes_a_snapshot_without_marking_it_stable(lab, capsys):
    rc, out = run(["release"], capsys)
    dirs = [p for p in (lab / "releases").iterdir() if p.is_dir()]
    assert rc == 0 and len(dirs) == 1 and dirs[0].name in out
    assert not (lab / "releases" / "STABLE").exists() and "aprobación explícita" in out    # congelar NO es aprobar


def test_status_lists_incidents_and_patterns(lab, capsys):
    rc, out = run(["status"], capsys)
    assert rc == 0 and "ninguno" in out
    Ledger(lab / "learning" / "incidents.jsonl").open(Incident("INC-0001", "v", "m", "algo falló", severity="alta"))
    rc, out = run(["status"], capsys)
    assert rc == 0 and "INC-0001 abierto alta" in out and "algo falló" in out


# ---- ceremonia de firma: identity / sign ----------------------------------------------------------------------------------------------
def new_key(lab, capsys, tmp_path, name="ana"):
    rc, out = run(["identity", "new", name, "--dir", str(tmp_path / "keys")], capsys)
    return rc, out, tmp_path / "keys" / f"{name}.key"


def test_identity_new_creates_a_private_key_outside_the_repo_and_refuses_to_overwrite(lab, capsys, tmp_path):
    rc, out, key = new_key(lab, capsys, tmp_path)
    assert rc == 0 and key.exists() and (key.stat().st_mode & 0o777) == 0o600 and "huella" in out
    rc, out, _ = new_key(lab, capsys, tmp_path)
    assert rc == 1 and out.startswith("error:")                      # no sobrescribe
    rc, out = run(["identity", "new", "../x", "--dir", str(tmp_path / "keys")], capsys)
    assert rc == 1 and out.startswith("error:")                      # nombre inválido
    rc, out = run(["identity", "new", "ana2", "--dir", str(lab / "dentro")], capsys)
    assert rc == 1 and out.startswith("error:") and not (lab / "dentro").exists()   # nunca dentro del proyecto


def test_identity_register_records_the_key_but_approves_nothing(lab, capsys, tmp_path):
    _, _, key = new_key(lab, capsys, tmp_path)
    pub = ceremony.load_key(key).public_bytes.hex()
    rc, out = run(["identity", "register", "--role", "approver", "--identity", "ana", "--pub", pub], capsys)
    assert rc == 0 and "NO aprueba nada" in out
    reg = json.loads((lab / "trust" / "registry.json").read_text())
    assert reg["ana"]["role"] == "approver" and reg["ana"]["public_key"] == pub
    assert approvals.valid_statements(lab, ceremony.current_release_id(lab), "approver") == []
    rc, out = run(["identity", "register", "--role", "approver", "--identity", "ana", "--pub", "zz"], capsys)
    assert rc == 1 and out.startswith("error:")                      # clave pública mal formada


def test_sign_refuses_without_an_interactive_terminal_unless_explicitly_allowed(lab, capsys, tmp_path, monkeypatch):
    _, _, key = new_key(lab, capsys, tmp_path)
    run(["identity", "register", "--role", "approver", "--identity", "ana", "--pub", ceremony.load_key(key).public_bytes.hex()], capsys)
    monkeypatch.delenv("QCE_ALLOW_NONINTERACTIVE_SIGN", raising=False)
    argv = ["sign", "--role", "approver", "--signer", "ana", "--key", str(key), "--verdict", "accept"]
    rc, out = run(argv, capsys)
    assert rc == 2 and "terminal interactiva" in out
    assert approvals.valid_statements(lab, ceremony.current_release_id(lab), "approver") == []     # no se firmó nada


def test_noninteractive_signature_with_the_explicit_override_is_valid_only_for_that_exact_code(lab, capsys, tmp_path, monkeypatch):
    _, _, key = new_key(lab, capsys, tmp_path)
    run(["identity", "register", "--role", "approver", "--identity", "ana", "--pub", ceremony.load_key(key).public_bytes.hex()], capsys)
    monkeypatch.setenv("QCE_ALLOW_NONINTERACTIVE_SIGN", "1")
    rid = ceremony.current_release_id(lab)
    rc, out = run(["sign", "--role", "approver", "--signer", "ana", "--key", str(key), "--verdict", "accept"], capsys)
    assert rc == 0 and "firmado:" in out and approvals.valid_statements(lab, rid, "approver") == ["ana"]
    (lab / "qce" / "m.py").write_text("def f(x):\n    return True\n")             # cualquier cambio de código…
    assert approvals.valid_statements(lab, ceremony.current_release_id(lab), "approver") == []   # …invalida la firma


def test_sign_rejects_wrong_role_unregistered_signer_and_a_key_that_is_not_theirs(lab, capsys, tmp_path, monkeypatch):
    _, _, key_ana = new_key(lab, capsys, tmp_path, "ana")
    _, _, key_bob = new_key(lab, capsys, tmp_path, "bob")
    run(["identity", "register", "--role", "approver", "--identity", "ana", "--pub", ceremony.load_key(key_ana).public_bytes.hex()], capsys)
    monkeypatch.setenv("QCE_ALLOW_NONINTERACTIVE_SIGN", "1")
    base = ["sign", "--signer", "ana", "--verdict", "accept"]
    for extra, fragment in ((["--role", "reviewer", "--key", str(key_ana)], "no como 'reviewer'"),
                            (["--role", "approver", "--key", str(key_bob)], "no corresponde"),
                            (["--role", "approver", "--key", str(tmp_path / "no-existe.key")], "error")):
        rc, out = run(base + extra, capsys)
        assert rc == 1 and fragment in out
    rc, out = run(["sign", "--signer", "nadie", "--role", "approver", "--key", str(key_ana), "--verdict", "accept"], capsys)
    assert rc == 1 and "no está registrada" in out
    assert approvals.valid_statements(lab, ceremony.current_release_id(lab), "approver") == []


class FakeTTY:
    def isatty(self):
        return True


@pytest.mark.parametrize("typed, expected_rc, signed", [("ana", 0, ["ana"]), ("mallory", 2, []), ("  ana  ", 0, ["ana"])])
def test_interactive_signature_requires_typing_the_signer_identity(lab, capsys, tmp_path, monkeypatch, typed, expected_rc, signed):
    _, _, key = new_key(lab, capsys, tmp_path)
    run(["identity", "register", "--role", "approver", "--identity", "ana", "--pub", ceremony.load_key(key).public_bytes.hex()], capsys)
    monkeypatch.setattr(sys, "stdin", FakeTTY())
    monkeypatch.setattr("builtins.input", lambda prompt="": typed)
    rc, out = run(["sign", "--role", "approver", "--signer", "ana", "--key", str(key), "--verdict", "accept"], capsys)
    assert rc == expected_rc and ("no confirmado" in out) == (expected_rc == 2)
    assert approvals.valid_statements(lab, ceremony.current_release_id(lab), "approver") == signed
