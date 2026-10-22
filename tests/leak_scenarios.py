"""Escenarios de carga y fugas de los puentes ctypes, en un PROCESO NUEVO (la memoria de pytest sería ruido). Uso: python tests/leak_scenarios.py <escenario> → JSON."""
import gc
import json
import os
import subprocess
import sys
import threading
import time

from qce.core.errors import QCEError
from qce.pqc import slhdsa as S
from qce.qkd.sources import OneTimeKeys
from qce.transport import tls13_psk as P

KEY = bytes(range(32))


class Reusable(OneTimeKeys):
    """Fuente que no consume: permite miles de apretones sin fabricar claves (la reserva exclusiva sí se mantiene)."""

    def commit(self, k):
        self.release(k)


def rss_mb():
    if os.path.exists("/proc/self/statm"):   # Linux: sin depender de `ps` (los contenedores mínimos no lo traen)
        return int(open("/proc/self/statm").read().split()[1]) * os.sysconf("SC_PAGE_SIZE") / (1 << 20)
    return int(subprocess.run(["ps", "-o", "rss=", "-p", str(os.getpid())], capture_output=True, text=True).stdout) / 1024


def heap_inuse_mb():
    """Bytes de montón EN USO (glibc `mallinfo2`), o None si no existe. A diferencia del RSS, NO cuenta la memoria libre que el asignador retiene por fragmentación:
    medido en Linux x86_64, el RSS crecía ≈ 600 B por apretón mientras los bytes en uso crecían ≈ 3 B (no había fuga; era fragmentación)."""
    try:
        import ctypes

        class MI(ctypes.Structure):
            _fields_ = [(n, ctypes.c_size_t) for n in ("arena", "ordblks", "smblks", "hblks", "hblkhd", "usmblks", "fsmblks", "uordblks", "fordblks", "keepcost")]
        libc = ctypes.CDLL("libc.so.6")
        libc.mallinfo2.restype = MI
        m = libc.mallinfo2()
        return (m.uordblks + m.hblkhd) / (1 << 20)
    except (OSError, AttributeError):
        return None


def snapshot():
    time.sleep(0.4)
    gc.collect()
    heap = heap_inuse_mb()
    return {"rss_mb": round(rss_mb(), 2), "heap_mb": None if heap is None else round(heap, 3), "fds": len(os.listdir("/dev/fd")), "threads": threading.active_count()}


def echo(c):
    c.send_frame(c.recv_frame()[::-1])


def run_handshakes(n, key, ok):
    srv = P.PskServer(Reusable({b"k": KEY}), echo, timeout=5).start()

    def one():
        try:
            c = P.connect_tcp("127.0.0.1", srv.port, b"k", key, timeout=5)
            c.send_frame(b"x" * 100)
            assert c.recv_frame() == b"x" * 100
            c.close()
            return True
        except (QCEError, OSError):
            return False
    for _ in range(50):
        one()
    before = snapshot()
    t0 = time.time()
    good = sum(one() for _ in range(n))
    dt = time.time() - t0
    after = snapshot()
    srv.close()
    return {"n": n, "ok": good, "per_second": round(n / dt), "before": before, "after": after}


def sc_handshakes():
    return run_handshakes(1500, KEY, True)


def sc_failing_handshakes():
    return run_handshakes(1500, bytes(32), False)


def sc_concurrent():
    keys = {b"k%d" % i: bytes([i + 1]) * 32 for i in range(16)}
    srv = P.PskServer(Reusable(keys), echo, timeout=10).start()

    def round_():
        results, lock = [], threading.Lock()

        def worker(kid):
            good = 0
            for _ in range(60):
                try:
                    c = P.connect_tcp("127.0.0.1", srv.port, kid, keys[kid], timeout=10)
                    c.send_frame(kid)
                    good += c.recv_frame() == kid[::-1]
                    c.close()
                except (QCEError, OSError):
                    pass
            with lock:
                results.append(good)
        ts = [threading.Thread(target=worker, args=(k,)) for k in keys]
        [t.start() for t in ts]
        [t.join(120) for t in ts]
        return sum(results)
    first_ok = round_()                      # ronda de calentamiento: los hilos crean sus arenas de malloc y sus pilas, que NO son una fuga
    before = snapshot()
    ok = [round_() for _ in range(3)]        # rondas medidas: una fuga real seguiría creciendo en cada una
    after = snapshot()
    srv.close()
    return {"workers": len(keys), "per_worker": 60, "ok_total": first_ok + sum(ok), "ok_per_round": ok, "before": before, "after": after}


def sc_slhdsa():
    k = S.SlhDsaPrivateKey.generate()
    sig = k.sign(b"m")
    for _ in range(100):
        S.slhdsa_verify(k.public_bytes(), b"m", sig)
    before = snapshot()
    for i in range(1, 5001):
        S.slhdsa_verify(k.public_bytes(), b"m", sig)
        if i % 100 == 0:
            S.SlhDsaPrivateKey.from_seed(bytes(48))
        if i % 500 == 0:
            k.sign(b"m")
    return {"before": before, "after": snapshot()}


SCEN = {"handshakes": sc_handshakes, "failing_handshakes": sc_failing_handshakes, "concurrent": sc_concurrent, "slhdsa": sc_slhdsa}

if __name__ == "__main__":
    print(json.dumps(SCEN[sys.argv[1]]()))
