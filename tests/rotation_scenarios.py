"""Escenarios del planificador de rotación, en un PROCESO NUEVO (ver tests/tls_scenarios.py). Uso: python tests/rotation_scenarios.py <escenario>"""
import json
import sys
import tempfile
import time
from pathlib import Path

from qce.transport import custody, tls13  # noqa: E402

from qce.key_management.keystore import KeyStore  # noqa: E402
from qce.transport import pki  # noqa: E402
from qce.transport.rotation import RotationScheduler  # noqa: E402


class Clock:
    t = time.time()

    def __call__(self):
        return self.t


def echo(conn, peer):
    tls13.send_frame(conn, tls13.recv_frame(conn)[::-1])


def ok(ctx, port):
    try:
        c = tls13.connect(ctx, "127.0.0.1", port, "localhost", timeout=5)
        tls13.send_frame(c, b"ab")
        r = tls13.recv_frame(c)
        c.close()
        return r == b"ba"
    except Exception:  # noqa: BLE001
        return False


def run(name):
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        clock = Clock()
        cu = custody.TlsKeyCustody(KeyStore(None, clock), d / "certs", clock=clock)
        ca, ck, cc = pki.issue_ca(d, days=30)
        kid1 = cu.provision_with_lab_ca(ck, cc, "localhost", 3600)
        srv = tls13.TlsServer(cu.server_context(), echo).start()
        sch = RotationScheduler(cu, ck, cc, "localhost", 3600, 600, server=srv, check_interval_s=0.05, clock=clock)
        if name == "tick":
            before = sch.tick()                      # recién creada: no toca
            clock.t += 3100                          # quedan 500 s < 600 de margen
            rotated = sch.tick()
            again = sch.tick()                       # ya rotada: no toca otra vez
            out = {"before_is_none": before is None, "rotated_is_new_id": rotated is not None and rotated != kid1, "again_is_none": again is None,
                   "active_is_new": cu.active_id() == rotated, "rotations": sch.rotations,
                   "server_serves_with_new_cert": ok(tls13.client_context(ca), srv.port)}
        elif name == "thread":
            sch.start()
            clock.t += 3100                          # el reloj avanza; nadie llama a rotate_if_due a mano
            deadline = time.time() + 5
            while time.time() < deadline and sch.rotations == 0:
                time.sleep(0.05)
            sch.stop()
            out = {"rotated_without_manual_call": sch.rotations >= 1, "active_changed": cu.active_id() != kid1,
                   "server_serves": ok(tls13.client_context(ca), srv.port), "thread_stopped": sch._thread is None}
        elif name == "no_scheduler":
            clock.t += 3100                          # el reloj avanza y NADIE llama a nada
            time.sleep(0.4)
            out = {"active_unchanged": cu.active_id() == kid1, "remaining_s": round(cu._store.info(kid1).not_after - clock(), 0)}
        elif name == "expired":
            clock.t += 7200                          # la clave YA caducó (nadie rotó a tiempo)
            sch2 = RotationScheduler(cu, ck, cc, "localhost", 3600, 600, server=srv, clock=clock)
            new = sch2.tick()
            out = {"recovered_from_expiry": new is not None and cu.active_id() == new, "server_serves": ok(tls13.client_context(ca), srv.port)}
        elif name == "survives_failures":
            events = []
            bad = RotationScheduler(cu, ck, cc, "localhost", 3600, 600, server=srv, clock=clock, on_event=lambda k, v: events.append(k))
            clock.t += 3100
            real = cu.rotate_if_due
            cu.rotate_if_due = lambda *a, **k: (_ for _ in ()).throw(OSError("CA caída"))
            r1 = bad.tick()                          # falla: no propaga
            cu.rotate_if_due = real
            r2 = bad.tick()                          # se recupera en el siguiente ciclo
            out = {"first_is_none": r1 is None, "errors": bad.errors, "last_error": bad.last_error, "recovered": r2 is not None, "events": events}
        else:
            raise SystemExit("escenario desconocido")
        srv.close()
    return out


if __name__ == "__main__":
    print(json.dumps(run(sys.argv[1])))
