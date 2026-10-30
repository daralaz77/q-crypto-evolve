"""Ítem 1.4 de la Fase 1: la rotación del certificado TLS ocurre SOLA (sin llamada manual) y sobrevive a fallos. OCSP y distribución de CRL: pendientes."""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from qce.transport.rotation import RotationScheduler

ROOT = Path(__file__).resolve().parent.parent


def scenario(name):
    env = {k: v for k, v in os.environ.items() if k != "OPENSSL_CONF"}
    env["PYTHONPATH"] = str(ROOT)
    r = subprocess.run([sys.executable, str(ROOT / "tests" / "rotation_scenarios.py"), name], capture_output=True, text=True, timeout=120, env=env, cwd=ROOT)
    assert r.returncode == 0, r.stderr[-800:]
    return json.loads(r.stdout.strip().splitlines()[-1])


def test_tick_rotates_only_when_due_and_the_server_keeps_serving():
    out = scenario("tick")
    assert out == {"before_is_none": True, "rotated_is_new_id": True, "again_is_none": True, "active_is_new": True, "rotations": 1, "server_serves_with_new_cert": True}


def test_background_thread_rotates_with_no_manual_call_and_stops_cleanly():
    out = scenario("thread")
    assert out["rotated_without_manual_call"] and out["active_changed"] and out["server_serves"] and out["thread_stopped"]


def test_an_already_expired_key_is_recovered():
    out = scenario("expired")
    assert out["recovered_from_expiry"] and out["server_serves"]


def test_a_failing_rotation_is_counted_not_propagated_and_retried():
    out = scenario("survives_failures")
    assert out["first_is_none"] and out["errors"] == 1 and out["last_error"] == "OSError" and out["recovered"]
    assert out["events"] == ["error", "rotated"]


@pytest.mark.parametrize("kw", [dict(check_interval_s=0), dict(renew_before_s=-1), dict(ttl_s=100, renew_before_s=100)])
def test_invalid_schedule_is_rejected(kw):
    base = dict(custody=None, ca_key=None, ca_cert=None, name="x", ttl_s=3600, renew_before_s=600)
    base.update(kw)
    with pytest.raises(ValueError):
        RotationScheduler(**base)


def test_canary_without_a_scheduler_nothing_rotates_by_itself():
    """El hueco que cierra 1.4: con el reloj adelantado y NADIE llamando, la clave activa no cambia aunque ya esté dentro del margen de renovación."""
    out = scenario("no_scheduler")
    assert out["active_unchanged"] and out["remaining_s"] < 600
