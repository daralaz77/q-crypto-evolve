"""Carga y fugas de los puentes ctypes: miles de apretones y firmas sin crecer en memoria, descriptores ni hilos, y todos correctos bajo concurrencia."""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from qce.transport import tls13_psk as P

ROOT = Path(__file__).resolve().parent.parent
try:
    P._load()
    HAVE = True
except P.PskTransportUnavailable:
    HAVE = False
needs = pytest.mark.skipif(not HAVE or sys.platform == "win32", reason="sin OpenSSL ≥ 3.5 o sin /dev/fd")
RSS_GROWTH_MB = 4.0   # sin `mallinfo2`: lo observado es < 0,5 MB; el margen cubre el ruido del asignador
HEAP_GROWTH_MB = 0.5  # con `mallinfo2` (glibc): bytes EN USO; lo observado es ≈ 0,01 MB. Una fuga de ≈ 170 B por apretón ya lo superaría


def scenario(name):
    env = {k: v for k, v in os.environ.items() if k != "OPENSSL_CONF"} | {"PYTHONPATH": str(ROOT)}
    r = subprocess.run([sys.executable, str(ROOT / "tests" / "leak_scenarios.py"), name], capture_output=True, text=True, cwd=ROOT, env=env, timeout=300)
    assert r.returncode == 0, r.stderr[-1200:]
    return json.loads(r.stdout.strip().splitlines()[-1])


def no_growth(r):
    b, a = r["before"], r["after"]
    if a.get("heap_mb") is not None and b.get("heap_mb") is not None:
        # En glibc el RSS mezcla fugas con fragmentación (medido: +600 B por apretón en Linux x86_64 sin fuga alguna): se mide lo que está en uso, que es más estricto.
        assert a["heap_mb"] - b["heap_mb"] < HEAP_GROWTH_MB, (b, a)
    else:
        assert a["rss_mb"] - b["rss_mb"] < RSS_GROWTH_MB, (b, a)
    assert a["fds"] == b["fds"] and a["threads"] == b["threads"], (b, a)


@needs
def test_1500_successful_handshakes_leak_no_memory_descriptors_or_threads():
    r = scenario("handshakes")
    assert r["ok"] == r["n"] == 1500 and r["per_second"] > 50          # 600/s observados; 50 solo detecta una degradación grave
    no_growth(r)


@needs
def test_1500_failing_handshakes_leak_nothing_either_and_none_succeeds():
    r = scenario("failing_handshakes")
    assert r["ok"] == 0
    no_growth(r)


@needs
def test_concurrent_clients_all_succeed_and_nothing_is_left_behind():
    r = scenario("concurrent")
    assert r["ok_per_round"] == [960, 960, 960] and r["ok_total"] == 4 * 960
    no_growth(r)       # tras calentar, tres rondas más de 16 hilos × 60 apretones no hacen crecer memoria, descriptores ni hilos


@needs
def test_slhdsa_verify_sign_and_seeded_keygen_leak_nothing():
    no_growth(scenario("slhdsa"))
