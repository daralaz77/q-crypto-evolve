"""Conformidad modelo-código de QIL1: trazas reales con atacante activo ↔ lemas y guardas de formal/qil1.spthy (ver qce/evolve/qil_conformance.py)."""
import copy
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from qce.evolve import qil_conformance as C

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def sessions():
    env = {k: v for k, v in os.environ.items() if k != "OPENSSL_CONF"}
    env["PYTHONPATH"] = str(ROOT)
    r = subprocess.run([sys.executable, str(ROOT / "tests" / "qkd_layer_scenarios.py"), "conformance"], capture_output=True, text=True, timeout=120, env=env, cwd=ROOT)
    assert r.returncode == 0, r.stderr[-1000:]
    return json.loads(r.stdout.strip().splitlines()[-1])


def names(tr, kind):
    return [e[1] for e in tr.events if e[0] == kind]


def test_real_traces_with_an_active_attacker_are_traces_of_the_model(sessions):
    tr = C.analyse(sessions)
    assert tr.problems == []
    assert names(tr, "ClientDone") == ["1-honesto", "4-legitimo-tras-ataque"] == names(tr, "ServerDone")
    assert names(tr, "ServerAbort") == ["3-atacante-etiqueta-falsa", "6-clave-equivocada-del-cliente", "7-mitm-certificado-falso"]
    assert "2-reutilizacion" not in names(tr, "ServerStart") and "5-hello-mal-formado" not in names(tr, "ServerStart")


def test_code_reproduces_the_models_verdicts_for_the_rogue_certificate_relay(sessions):
    """Con el certificado falso: el servidor real empieza (el atacante retransmite) pero el cliente no completa, y no hay ClientDone en esa sesión."""
    s = next(x for x in sessions if x["name"].startswith("7-"))
    assert s["client"]["outcome"] == "AuthenticationFailure" and s["server"]["outcome"] != "ok"
    assert s["client"]["bind"] != s["server"]["bind"] and s["client"]["cert"] != s["server"]["cert"]


def tamper(sessions, name, fn):
    ss = copy.deepcopy(sessions)
    fn(next(s for s in ss if s["name"].startswith(name)))
    return C.analyse(ss).problems


def test_the_oracle_detects_a_client_more_permissive_than_the_model(sessions):
    assert any("más permisivo" in p for p in tamper(sessions, "7-", lambda s: s["client"].__setitem__("outcome", "ok")))


def test_the_oracle_detects_a_client_that_refuses_a_valid_accept(sessions):
    assert any("no aceptó" in p for p in tamper(sessions, "1-", lambda s: s["client"].__setitem__("outcome", "AuthenticationFailure")))


def test_the_oracle_detects_a_server_that_consumes_without_a_valid_client_tag(sessions):
    def f(s):
        s["server"]["calls"] = [c for c in s["server"]["calls"] if c[0] != "release"] + [["commit", s["server"]["calls"][0][1], True]]
    assert any("consumió la clave" in p for p in tamper(sessions, "3-", f))


def test_the_oracle_detects_a_server_that_does_not_return_the_key_after_an_abort(sessions):
    def f(s):
        s["server"]["calls"] = [c for c in s["server"]["calls"] if c[0] != "release"]
    probs = tamper(sessions, "3-", f)
    assert any("exactamente un commit o un release" in p for p in probs) and any("reserva" in p for p in probs)   # y la sesión 4 ya no puede reservar


def test_the_oracle_detects_a_server_that_touches_the_key_source_on_a_malformed_hello(sessions):
    assert any("HELLO mal formado" in p for p in tamper(sessions, "5-", lambda s: s["server"]["calls"].append(["reserve", "00", True])))


def test_the_oracle_detects_reuse_after_completion(sessions):
    def f(s):
        s["server"]["calls"] = [["reserve", s["server"]["calls"][0][1], True], ["release", s["server"]["calls"][0][1], True]]
    assert any("reserva" in p for p in tamper(sessions, "2-", f))


def test_the_oracle_detects_a_wrong_server_accept_tag(sessions):
    def f(s):
        a = bytearray(bytes.fromhex(s["server"]["sent"][0])); a[-1] ^= 1
        s["server"]["sent"][0] = a.hex()
    assert any("ACCEPT del servidor no es el del modelo" in p for p in tamper(sessions, "1-", f))


def test_the_oracle_detects_a_channel_agreement_violation_in_the_events():
    tr = C.Trace(events=[("ClientStart", "x", b"k", b"n"), ("ServerStart", "x", b"k", b"t", b"B1", b"F"),
                         ("ClientDone", "x", b"k", b"t", b"a", b"b", b"B2", b"F")])
    C.check_lemmas(tr)
    assert any("channel_agreement" in p for p in tr.problems)
