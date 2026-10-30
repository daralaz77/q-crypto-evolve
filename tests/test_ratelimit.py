"""Ítem 1.2 de la Fase 1: límite de tasa por origen en el transporte TLS y en QIL1 (T5/T43)."""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from qce.core.errors import PolicyViolation
from qce.core.ratelimit import OriginRateLimiter, RateLimited

ROOT = Path(__file__).resolve().parent.parent


class Clock:
    t = 100.0

    def __call__(self):
        return self.t


def test_burst_then_refill_with_a_simulated_clock():
    c = Clock()
    rl = OriginRateLimiter(rate_per_s=1.0, burst=3, clock=c)
    assert [rl.allow("a") for _ in range(4)] == [True, True, True, False]  # ráfaga de 3 y se corta
    c.t += 1.0
    assert rl.allow("a") and not rl.allow("a")  # 1 s = 1 ficha
    c.t += 100
    assert [rl.allow("a") for _ in range(4)] == [True, True, True, False]  # nunca supera la ráfaga


def test_origins_are_independent_and_legitimate_traffic_passes():
    rl = OriginRateLimiter(rate_per_s=0.001, burst=2, clock=Clock())
    assert rl.allow("atacante") and rl.allow("atacante") and not rl.allow("atacante")
    assert rl.allow("legitimo") and rl.allow("legitimo")  # otro origen no se ve afectado
    assert rl.denied == 1


def test_memory_is_bounded_against_many_spoofed_origins():
    rl = OriginRateLimiter(rate_per_s=1, burst=1, max_origins=100, clock=Clock())
    for i in range(10_000):
        rl.allow(f"10.0.{i // 256}.{i % 256}")
    assert rl.tracked_origins <= 100


def test_check_raises_a_policy_violation_subclass():
    rl = OriginRateLimiter(rate_per_s=0.001, burst=1, clock=Clock())
    rl.check("x")
    with pytest.raises(RateLimited) as e:
        rl.check("x")
    assert isinstance(e.value, PolicyViolation)


@pytest.mark.parametrize("bad", [(0, 1), (1, 0), (-1, 1)])
def test_invalid_parameters_are_rejected(bad):
    with pytest.raises(ValueError):
        OriginRateLimiter(bad[0], bad[1])


def scenario(name):
    env = {k: v for k, v in os.environ.items() if k != "OPENSSL_CONF"}
    env["PYTHONPATH"] = str(ROOT)
    r = subprocess.run([sys.executable, str(ROOT / "tests" / "ratelimit_scenarios.py"), name], capture_output=True, text=True, timeout=120, env=env, cwd=ROOT)
    assert r.returncode == 0, r.stderr[-800:]
    return json.loads(r.stdout.strip().splitlines()[-1])


def test_tls_server_drops_excess_connections_before_any_tls_work():
    out = scenario("tls_flood")
    assert out["legit_ok"] is True            # el tráfico legítimo (otro origen simulado con reloj) sigue pasando
    assert out["rate_limited"] >= 5           # la inundación se cortó antes del apretón
    assert out["handshakes_attempted_by_server"] <= out["burst"] + 1  # solo la ráfaga llegó a hacer TLS


def test_canary_without_a_limiter_every_connection_reaches_the_tls_handshake():
    out = scenario("tls_flood_unlimited")
    assert out["rate_limited"] == 0 and out["handshakes_attempted_by_server"] >= 10


def test_qil1_server_refuses_before_reserving_a_key_when_the_origin_is_limited():
    out = scenario("qil1_limited")
    assert out["second_attempt_error"] == "RateLimited"
    assert out["keys_reserved_by_the_second_attempt"] == 0  # no retiene ninguna clave
