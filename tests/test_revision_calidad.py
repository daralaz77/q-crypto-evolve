"""Revisión de calidad y seguridad (2026-10-30). Cada corrección tiene su prueba, que FALLA sin ella (se comprobó antes de corregir)."""
import ast
import json
import os
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from qce.core.errors import AuthenticationFailure, IntegrityError, QCEError
from qce.core.policy import Policy
from qce.core.ratelimit import OriginRateLimiter
from qce.key_management import vault
from qce.pqc.hybrid import HybridSigPrivateKey
from qce.qkd.broker import KeyBroker
from qce.qkd.contract import ErrorCategory, QKDDeviceError
from qce.qkd.devices import DeviceRegistry, SimulatedAdapter, SimulatedLink
from qce.security import approvals

ROOT = Path(__file__).resolve().parent.parent


# ---- 1. QIL1: un contador-nonce compartido entre hilos no puede repetirse -------------------------------------------------------------
def test_qil1_layer_never_reuses_a_nonce_when_two_threads_write():
    env = dict(os.environ, PYTHONPATH=str(ROOT))
    r = subprocess.run([sys.executable, str(ROOT / "tests" / "layer_lock_scenarios.py")], capture_output=True, text=True, timeout=120, env=env, cwd=ROOT)
    assert r.returncode == 0, r.stderr[-800:]
    out = json.loads(r.stdout.strip().splitlines()[-1])
    assert out["nonces"] == [0, 1]                  # sin candado: [0, 0] (mismo nonce, mismo flujo de clave)
    assert out["read"] == ["dos", "uno"]            # y el receptor, que exige el orden del contador, autentica ambos
    assert out["read_nonces"] == [0, 1]             # lo mismo al LEER desde dos hilos: cada uno usa su propio contador


# ---- 2. KeyBroker: las transiciones de estado se serializan (varios hilos por servidor comparten el broker) --------------------------
def broker_with_one_key(tmp_path):
    t = [1000.0]
    link = SimulatedLink("L1")
    reg = DeviceRegistry(None, lambda: t[0])
    dev = SimulatedAdapter("devA", link, clock=lambda: t[0])
    reg.enroll("devA", "SIMULATION", "sim", dev.firmware, dev.identity.public_bytes, approved_by="darwin")
    dev.initialize({"registry": reg})
    broker = KeyBroker(Policy(allow_simulated_qkd=True), reg, None, lambda: t[0], {"L1": {"sess"}})
    broker.attach("L1", dev)
    link.generate(1)
    broker.refill("L1")
    return broker, link


def blocked_while_locked(broker, call):
    """¿`call` espera mientras otra operación tiene el candado del broker? (sin candado no hay nada que esperar)"""
    done = threading.Event()
    with broker._lock:
        t = threading.Thread(target=lambda: (call(), done.set()), daemon=True)
        t.start()
        waited = not done.wait(0.3)
    t.join(5)
    return waited and done.is_set()


def test_broker_state_changes_wait_for_the_broker_lock(tmp_path):
    b, link = broker_with_one_key(tmp_path)
    assert blocked_while_locked(b, lambda: b.status("L1"))
    assert blocked_while_locked(b, lambda: b.reserve("L1", "sess"))
    kid = next(iter(b._refs))
    own = type(b).metadata.__wrapped__                                      # `peek` también pasa por `metadata` (con candado): se la quita para ver el candado PROPIO de `peek`
    b.metadata = lambda k: own(b, k)
    assert blocked_while_locked(b, lambda: b.peek(kid, "sess"))
    del b.metadata
    assert blocked_while_locked(b, lambda: b.release(kid, "sess"))
    b.reserve("L1", "sess")
    assert blocked_while_locked(b, lambda: b.consume(kid, "sess"))
    assert blocked_while_locked(b, lambda: b.metadata(kid))
    link.generate(1)
    assert blocked_while_locked(b, lambda: b.refill("L1"))     # registrar la clave nueva (comprobar duplicado + guardar) espera al candado
    assert blocked_while_locked(b, lambda: b.revoke(kid, "prueba"))


def test_broker_hands_a_single_key_to_exactly_one_of_many_concurrent_reservers(tmp_path):
    old = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)  # máximo cruce de hilos
    try:
        for _ in range(20):
            b, _ = broker_with_one_key(tmp_path)
            wins, start = [], threading.Barrier(8)

            def go():
                start.wait()
                try:
                    wins.append(b.reserve("L1", "sess"))
                except QKDDeviceError as exc:
                    assert exc.category is ErrorCategory.KEY_EXHAUSTION
            ts = [threading.Thread(target=go) for _ in range(8)]
            [t.start() for t in ts]
            [t.join(10) for t in ts]
            assert len(wins) == 1
    finally:
        sys.setswitchinterval(old)


# ---- 3. EpochAnchor: el ancla no retrocede aunque dos procesos la adelanten a la vez -------------------------------------------------
def test_epoch_anchor_cannot_go_back_when_two_writers_race(tmp_path, monkeypatch):
    a = vault.EpochAnchor(tmp_path / "anchor.json")
    a.advance(5)
    real_replace, gate = os.replace, threading.Barrier(2)

    def slow_replace(src, dst):
        if '"epoch": 7' in Path(src).read_text():  # el escritor del 7 llega tarde al reemplazo: sin candado, el 7 queda al final y el ancla retrocede de 9 a 7
            threading.Event().wait(0.4)
        real_replace(src, dst)
    monkeypatch.setattr(os, "replace", slow_replace)
    real_read = vault.EpochAnchor.read

    def read_together(self):
        try:
            gate.wait(0.3)  # los dos leen el 5 a la vez (con candado, el segundo espera fuera y el plazo se ignora)
        except threading.BrokenBarrierError:
            pass
        return real_read(self)
    monkeypatch.setattr(vault.EpochAnchor, "read", read_together)
    errors = []

    def adv(n):
        try:
            a.advance(n)
        except IntegrityError as exc:
            errors.append(str(exc))
    ts = [threading.Thread(target=adv, args=(n,)) for n in (7, 9)]
    [t.start() for t in ts]
    [t.join(10) for t in ts]
    monkeypatch.undo()
    assert vault.EpochAnchor(tmp_path / "anchor.json").read() == 9


def test_a_failed_anchor_or_vault_write_keeps_the_previous_file(tmp_path, monkeypatch):
    from qce.key_management.keystore import KeyStore, Purpose
    a, vp = vault.EpochAnchor(tmp_path / "anchor.json"), tmp_path / "vault.bin"
    a.advance(3)
    store = KeyStore()
    store.create(Purpose.ENCRYPT, 100)
    vault.save(store, vp, "frase", n=2**14)
    before = (a.path.read_bytes(), vp.read_bytes())

    def boom(src, dst):
        raise OSError("disco lleno")
    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(OSError):
        a.advance(4)
    store.create(Purpose.SIGN, 100)
    with pytest.raises(OSError):
        vault.save(store, vp, "frase", n=2**14)
    monkeypatch.undo()
    assert (a.path.read_bytes(), vp.read_bytes()) == before             # ni truncados ni a medias
    assert sorted(p.name for p in tmp_path.iterdir()) == ["anchor.json", "anchor.json.lock", "vault.bin"]  # sin temporales sobrantes


# ---- 4. Límite de tasa: todo un /64 de IPv6 es UN origen --------------------------------------------------------------------------
def test_ipv6_origins_are_aggregated_by_their_slash_64():
    key = OriginRateLimiter.origin_key
    assert key("2001:db8:0:1::1") == key("2001:db8:0:1:ffff:ffff:ffff:ffff") == "2001:db8:0:1::/64"
    assert key("2001:db8:0:2::1") != key("2001:db8:0:1::1")
    assert key("::ffff:203.0.113.9") == "203.0.113.9" == key("203.0.113.9")   # IPv4 asignada a IPv6 = la misma IPv4
    assert key("fe80::1%en0") == "fe80::/64"                                   # sin identificador de zona
    assert key("atacante") == "atacante"                                       # lo que no es una IP no se toca


def test_a_flood_from_one_slash_64_shares_one_budget():
    rl = OriginRateLimiter(rate_per_s=0.001, burst=2, clock=lambda: 100.0)
    assert [rl.allow(f"2001:db8:0:1::{i:x}") for i in range(1, 5)] == [True, True, False, False]  # 4 direcciones, 1 origen
    assert rl.allow("2001:db8:0:2::1")                                                              # otro /64 no se ve afectado
    assert rl.tracked_origins == 2


# ---- 5. Declaraciones firmadas: nada de rutas ni comodines en release_id/rol; el registro de confianza se escribe de forma atómica ---
@pytest.fixture(scope="module")
def key():
    return HybridSigPrivateKey.generate()


@pytest.mark.parametrize("rid", ["../fuera", "a/b", "a*", "a?b", "[x]", "", "x" * 65, "con espacio"])
def test_release_id_cannot_escape_the_reviews_folder_or_widen_a_glob(tmp_path, key, rid):
    root = tmp_path / "repo"
    root.mkdir()
    with pytest.raises(QCEError):
        approvals.sign_statement(root, key, "reviewer", "ana", rid, "accept")
    with pytest.raises(QCEError):
        approvals.valid_statements(root, rid, "reviewer")
    with pytest.raises(QCEError):
        approvals.has_valid_veto(root, rid, "reviewer")             # función pública: no depende de que quien la llame ya haya validado
    assert not [p for p in tmp_path.rglob("*") if p.is_file()]  # no se creó nada, ni dentro ni fuera de la raíz


def test_role_cannot_be_used_as_a_path(tmp_path, key):
    root = tmp_path / "repo"
    root.mkdir()
    with pytest.raises(QCEError):
        approvals.sign_statement(root, key, "../x", "ana", "abc123", "accept")


def test_a_failed_registry_write_keeps_the_previous_trust_registry_intact(tmp_path, monkeypatch):
    root = tmp_path
    approvals.register(root, "reviewer", "ana", b"\x01" * 32)
    reg = root / "trust" / "registry.json"
    before = reg.read_bytes()

    def boom(src, dst):
        raise OSError("disco lleno")
    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(OSError):
        approvals.register(root, "approver", "luis", b"\x02" * 32)
    monkeypatch.undo()
    assert reg.read_bytes() == before                                   # ni truncado ni a medias
    assert not [p for p in (root / "trust").iterdir() if p.name != "registry.json"]  # sin temporales sobrantes


# ---- 6. Higiene: texto con codificación explícita y procesos externos con plazo ----------------------------------------------------
CODE = [ROOT / "qce", ROOT / "qce_kme.py", ROOT / "tools", ROOT / "panel", ROOT / "conformance", ROOT / "benchmarks", ROOT / "examples"]
NO_TIMEOUT_OK = {("qce/cli.py", "_cmd_test")}  # `qce test` es el ejecutor interactivo de pytest: el usuario lo interrumpe con Ctrl-C


def code_files():
    for base in CODE:
        for f in ([base] if base.is_file() else sorted(base.rglob("*.py"))):
            rel = f.relative_to(ROOT).as_posix()
            if "/tests/" not in rel and "/mutants/" not in rel and "node_modules" not in rel:
                yield f, rel, ast.parse(f.read_text(encoding="utf-8"))


def calls_with_function(tree):
    for fn in [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))] + [tree]:
        for n in ast.walk(fn):
            if isinstance(n, ast.Call):
                yield getattr(fn, "name", "<módulo>"), n


def test_text_files_are_read_and_written_with_an_explicit_encoding():
    bad = []
    for _, rel, tree in code_files():
        for n in ast.walk(tree):
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in ("read_text", "write_text") and not any(k.arg == "encoding" for k in n.keywords):
                bad.append(f"{rel}:{n.lineno}")
    assert not bad, "read_text/write_text sin encoding: " + ", ".join(bad)


def test_every_external_process_has_a_timeout():
    bad = []
    for _, rel, tree in code_files():
        seen = set()
        for fname, n in calls_with_function(tree):
            if (isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name) and n.func.value.id == "subprocess"
                    and n.func.attr in ("run", "call", "check_call", "check_output") and id(n) not in seen):
                seen.add(id(n))
                if not any(k.arg == "timeout" for k in n.keywords) and (rel, fname) not in NO_TIMEOUT_OK:
                    bad.append(f"{rel}:{n.lineno}")
    assert not bad, "subprocess sin timeout: " + ", ".join(bad)


@pytest.mark.parametrize("args", [["--master", "../x"], ["--slave", "a b"], ["--days", "0"], ["--max-keys", "0"], ["--port", "70000"]])
def test_kme_emulator_rejects_arguments_that_become_file_names_or_make_no_sense(args, tmp_path):
    qce_kme = pytest.importorskip("qce_kme")  # vive fuera de `qce/` a propósito: el sandbox de mutación no lo copia
    with pytest.raises(SystemExit) as e:
        qce_kme.main([*args, "--dir", str(tmp_path / "pki"), "--seconds", "0.1"])
    assert e.value.code == 2 and not (tmp_path / "pki").exists()  # se rechaza ANTES de crear nada
