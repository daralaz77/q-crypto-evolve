"""Escenarios del límite de tasa por origen, en un PROCESO NUEVO (ver tests/tls_scenarios.py para el porqué).
Uso: python tests/ratelimit_scenarios.py <escenario>  →  imprime un JSON (última línea)."""
import json
import socket
import sys
import tempfile
import time
from pathlib import Path

from qce.transport import qkd_layer as Q  # noqa: E402  (importa tls13 primero)
from qce.transport import tls13  # noqa: E402

from qce.core.ratelimit import OriginRateLimiter  # noqa: E402
from qce.transport import pki  # noqa: E402

BURST = 3


def echo(conn, peer):
    tls13.send_frame(conn, tls13.recv_frame(conn)[::-1])


def flood(port, n):
    """n conexiones TCP que mandan basura (el servidor las intenta como apretón TLS y fallan rápido)."""
    for _ in range(n):
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=2)
            s.sendall(b"\x16\x03\x01garbagegarbage")
            s.close()
        except OSError:
            pass


def sc_tls_flood(limited: bool):
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        ca, ck, cc = pki.issue_ca(d)
        cert, key = pki.issue_leaf(d, ck, cc, "localhost", server=True)
        limiter = OriginRateLimiter(rate_per_s=0.001, burst=BURST) if limited else None
        srv = tls13.TlsServer(tls13.server_context(cert, key), echo, limiter=limiter).start()
        legit_ok = False
        c = tls13.connect(tls13.client_context(ca), "127.0.0.1", srv.port, "localhost", timeout=5)  # 1.ª conexión legítima (dentro de la ráfaga)
        tls13.send_frame(c, b"ping")
        legit_ok = tls13.recv_frame(c) == b"gnip"
        c.close()
        flood(srv.port, 12)
        time.sleep(1.5)
        out = {"legit_ok": legit_ok, "rate_limited": srv.rate_limited, "handshakes_attempted_by_server": srv.failed_handshakes + 1, "burst": BURST}
        srv.close()
    return out


class Source:
    """Fuente QKD mínima que cuenta las reservas."""

    def __init__(self):
        self.reserved = 0

    def reserve(self, kid):
        self.reserved += 1
        return bytes(range(32))

    def commit(self, kid):
        pass

    def release(self, kid):
        pass


def sc_qil1_limited_real():
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        ca, ck, cc = pki.issue_ca(d)
        cert, key = pki.issue_leaf(d, ck, cc, "localhost", server=True)
        import ssl
        cert_der = ssl.PEM_cert_to_DER_cert(cert.read_text())
        src, limiter, results = Source(), OriginRateLimiter(rate_per_s=0.001, burst=1), []

        def handle(conn, peer):
            before = src.reserved
            try:
                Q.server_layer(conn, src, cert_der, limiter=limiter)
                results.append(("ok", src.reserved - before))
            except Exception as exc:  # noqa: BLE001
                results.append((type(exc).__name__, src.reserved - before))
        srv = tls13.TlsServer(tls13.server_context(cert, key), handle).start()
        for _ in range(2):  # dos intentos desde el MISMO origen: el 2.º debe rechazarse antes de reservar
            c = tls13.connect(tls13.client_context(ca), "127.0.0.1", srv.port, "localhost", timeout=5)
            try:
                Q.client_layer(c, b"qkd-key-0001", bytes(range(32)))
            except Exception:  # noqa: BLE001
                pass
            c.close()
            time.sleep(0.5)
        srv.close()
    first, second = results[0], results[1]
    return {"first_attempt": first[0], "second_attempt_error": second[0], "keys_reserved_by_the_second_attempt": second[1]}


if __name__ == "__main__":
    name = sys.argv[1]
    print(json.dumps({"tls_flood": lambda: sc_tls_flood(True), "tls_flood_unlimited": lambda: sc_tls_flood(False), "qil1_limited": sc_qil1_limited_real}[name]()))
