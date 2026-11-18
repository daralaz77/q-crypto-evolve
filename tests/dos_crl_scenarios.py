"""Escenarios de la ronda 7 (agotamiento de recursos del servidor TLS y revocación con CRL). Cada uno corre en un PROCESO NUEVO, como tls_scenarios.py.
Uso: python tests/dos_crl_scenarios.py <escenario>  →  imprime un JSON."""
import json
import sys

import errno  # noqa: E402
import socket  # noqa: E402
import ssl  # noqa: E402
import tempfile  # noqa: E402
import threading  # noqa: E402
import time  # noqa: E402
from pathlib import Path  # noqa: E402

from qce.transport import tls13  # noqa: E402  (antes que `cryptography`: fija OPENSSL_CONF)


def echo_handler(conn, peer):
    tls13.send_frame(conn, tls13.recv_frame(conn)[::-1])


def pki_lab(d):
    from qce.transport import pki as P
    ca, ck, cc = P.issue_ca(d)
    cert, key = P.issue_leaf(d, ck, cc, "localhost", server=True)
    return P, ca, ck, cc, cert, key


def closed_after(sock, limit):
    """Segundos hasta que el servidor corta (EOF o error); None si sigue abierta pasado `limit`."""
    t0 = time.monotonic()
    sock.settimeout(0.5)
    while time.monotonic() - t0 < limit:
        try:
            if sock.recv(1) == b"":
                return time.monotonic() - t0
        except socket.timeout:
            continue
        except OSError:
            return time.monotonic() - t0
    return None


def try_roundtrip(ctx, port):
    try:
        c = tls13.connect(ctx, "127.0.0.1", port, "localhost", timeout=5)
        tls13.send_frame(c, b"ping")
        r = tls13.recv_frame(c)
        c.close()
        return r.decode()
    except (ssl.SSLError, OSError, tls13.MalformedMessage) as exc:
        return type(exc).__name__


def try_ctx_error(fn):
    try:
        fn()
        return "ok"
    except Exception as exc:  # noqa: BLE001
        return type(exc).__name__


def run(name):
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        P, ca, ck, cc, cert, key = pki_lab(d)
        if name == "slowloris":
            # un byte cada 0,3 s: antes mantenía vivo el apretón (plazo por operación de 10 s) indefinidamente
            srv = tls13.TlsServer(tls13.server_context(cert, key), echo_handler, handshake_timeout=1.0).start()
            s = socket.create_connection(("127.0.0.1", srv.port))
            s.send(b"\x16\x03\x01\x04\x00")                                # cabecera de registro TLS válida que anuncia 1024 bytes: OpenSSL espera a tener el registro entero
            stop = threading.Event()

            def drip():
                while not stop.is_set():
                    try:
                        s.send(b"A")
                    except OSError:
                        return
                    time.sleep(0.3)
            threading.Thread(target=drip, daemon=True).start()
            t = closed_after(s, 6)
            stop.set()
            ok_after = try_roundtrip(tls13.client_context(ca), srv.port)
            return {"closed_in": t, "failed": srv.failed_handshakes, "ok_after": ok_after}
        if name == "busy_cap":
            gate = threading.Event()

            def hold(conn, peer):
                gate.wait(10)
            srv = tls13.TlsServer(tls13.server_context(cert, key), hold, max_connections=2).start()
            held = [tls13.connect(tls13.client_context(ca), "127.0.0.1", srv.port, "localhost", timeout=5) for _ in range(2)]
            time.sleep(0.3)
            extra = socket.create_connection(("127.0.0.1", srv.port))
            t = closed_after(extra, 3)
            busy = srv.rejected_busy
            gate.set()
            for c in held:
                c.close()
            time.sleep(0.5)                                           # los hilos terminan y devuelven su hueco
            c = tls13.connect(tls13.client_context(ca), "127.0.0.1", srv.port, "localhost", timeout=5)   # con hueco libre, otra conexión entra
            c.close()
            return {"extra_closed_in": t, "rejected_busy": busy, "rejected_after": srv.rejected_busy, "served_after_release": True}
        if name == "lifetime":
            def idle(conn, peer):
                try:
                    tls13.recv_frame(conn)
                except (OSError, tls13.MalformedMessage, ssl.SSLError):
                    pass
            srv = tls13.TlsServer(tls13.server_context(cert, key), idle, max_lifetime=1.0).start()
            c = tls13.connect(tls13.client_context(ca), "127.0.0.1", srv.port, "localhost", timeout=5)
            t0 = time.monotonic()
            c.settimeout(6)
            try:
                got = c.recv(1)
            except (OSError, ssl.SSLError):
                got = b""
            return {"closed_in": time.monotonic() - t0 if got == b"" else None}
        if name == "accept_survives":
            srv = tls13.TlsServer(tls13.server_context(cert, key), echo_handler)

            class Flaky:
                """Envuelve el socket de escucha y falla las dos primeras aceptaciones como lo haría un proceso sin descriptores."""
                def __init__(self, real):
                    self.real, self.n = real, 0

                def accept(self):
                    if self.n < 2:
                        self.n += 1
                        raise OSError(errno.EMFILE, "demasiados archivos abiertos")
                    return self.real.accept()

                def __getattr__(self, a):
                    return getattr(self.real, a)
            flaky = Flaky(srv._ls)
            srv._ls = flaky
            srv.start()
            r = try_roundtrip(tls13.client_context(ca), srv.port)
            alive = srv._thread.is_alive()
            srv.close()
            time.sleep(0.3)
            return {"echo": r, "failures_injected": flaky.n, "alive": alive, "stopped_after_close": not srv._thread.is_alive()}
        if name == "origin_cap":
            gate = threading.Event()

            def hold(conn, peer):
                gate.wait(10)
            srv = tls13.TlsServer(tls13.server_context(cert, key), hold, max_connections=10, max_per_origin=2).start()
            held = [tls13.connect(tls13.client_context(ca), "127.0.0.1", srv.port, "localhost", timeout=5) for _ in range(2)]
            time.sleep(0.3)
            extra = socket.create_connection(("127.0.0.1", srv.port))
            t = closed_after(extra, 3)
            out = {"extra_closed_in": t, "rejected_origin": srv.rejected_origin, "rejected_busy": srv.rejected_busy}
            gate.set()
            for c in held:
                c.close()
            time.sleep(0.5)
            c = tls13.connect(tls13.client_context(ca), "127.0.0.1", srv.port, "localhost", timeout=5)   # al liberarse sus huecos, el origen vuelve a entrar
            c.close()
            out["served_after_release"] = True
            return out
        if name == "chain_crl":
            from cryptography import x509
            ca2, ck2, cc2 = P.issue_ca(d / "cadena", path_length=1) if (d / "cadena").mkdir() is None else None
            ip, ik, ic = P.issue_intermediate(d / "cadena", ck2, cc2)
            lcert, lkey = P.issue_leaf(d / "cadena", ik, ic, "localhost", server=True)
            chain = d / "cadena" / "chain.pem"
            chain.write_bytes(Path(lcert).read_bytes() + Path(ip).read_bytes())            # el servidor envía hoja + intermedia
            trust = d / "cadena" / "trust.pem"
            trust.write_bytes(Path(ca2).read_bytes() + Path(ip).read_bytes())              # el cliente confía en la raíz y conoce la intermedia
            leaf = x509.load_pem_x509_certificate(Path(lcert).read_bytes())
            inter = ic
            crl_int = P.issue_crl(d / "cadena", ik, ic, [], name="int.pem")
            crl_int_rev = P.issue_crl(d / "cadena", ik, ic, [leaf], name="int-rev.pem")
            crl_root = P.issue_crl(d / "cadena", ck2, cc2, [], name="root.pem")
            crl_root_rev = P.issue_crl(d / "cadena", ck2, cc2, [inter], name="root-rev.pem")
            srv = tls13.TlsServer(tls13.server_context(chain, lkey), echo_handler).start()

            def attempt(**kw):
                try:
                    return try_roundtrip(tls13.client_context(trust, **kw), srv.port)
                except Exception as exc:  # noqa: BLE001
                    return type(exc).__name__
            out = {"both_empty": attempt(crl_file=[crl_int, crl_root]),
                   "leaf_revoked": attempt(crl_file=[crl_int_rev, crl_root]),
                   "intermediate_revoked": attempt(crl_file=[crl_int, crl_root_rev]),
                   "root_crl_missing": attempt(crl_file=[crl_int]),
                   "leaf_mode_misses_intermediate": attempt(crl_file=crl_int),             # límite declarado del modo hoja
                   "issuer_not_in_trust": try_ctx_error(lambda: tls13.client_context(ca2, crl_file=[crl_int, crl_root])),
                   "chain_with_min_number": try_ctx_error(lambda: tls13.client_context(trust, crl_file=[crl_int, crl_root], min_crl_number=1)),
                   "empty_list": try_ctx_error(lambda: tls13.client_context(trust, crl_file=[]))}
            srv.close()
            return out
        if name == "crl_pin":
            from qce.transport.crl import CrlPin
            pin_file = d / "pin" / "crl-pin.json"
            pin = CrlPin(pin_file)
            out = {}
            def ctx(c):
                return tls13.client_context(ca, crl_file=c, crl_pin=pin)
            out["first"] = try_ctx_error(lambda: ctx(P.issue_crl(d, ck, cc, [], number=5, name="n5.pem")))
            out["older"] = try_ctx_error(lambda: ctx(P.issue_crl(d, ck, cc, [], number=3, name="n3.pem")))
            out["same"] = try_ctx_error(lambda: ctx(P.issue_crl(d, ck, cc, [], number=5, name="n5b.pem")))
            out["newer"] = try_ctx_error(lambda: ctx(P.issue_crl(d, ck, cc, [], number=6, name="n6.pem")))
            _ca2, ck2, _cc2 = P.issue_ca(d / "falsa", cn=cc.subject.rfc4514_string().removeprefix("CN=")) if (d / "falsa").mkdir() is None else None
            out["forged_high"] = try_ctx_error(lambda: ctx(P.issue_crl(d / "falsa", ck2, cc, [], number=99, name="n99.pem")))
            out["floor_after_forgery"] = json.loads(pin_file.read_text())
            out["still_older_after_forgery"] = try_ctx_error(lambda: ctx(P.issue_crl(d, ck, cc, [], number=5, name="n5c.pem")))
            out["pin_without_crl"] = try_ctx_error(lambda: tls13.client_context(ca, crl_pin=pin))
            out["server_pin_without_mtls"] = try_ctx_error(lambda: tls13.server_context(cert, key, crl_pin=pin))
            return out
        if name == "mtls_crl":
            ccert, ckey = P.issue_leaf(d, ck, cc, "cliente", server=False)
            bcert, bkey = P.issue_leaf(d, ck, cc, "cliente-malo", server=False)
            from cryptography import x509
            bad = x509.load_pem_x509_certificate(Path(bcert).read_bytes())
            crl = P.issue_crl(d, ck, cc, [bad], name="clientes.pem", number=7)
            srv = tls13.TlsServer(tls13.server_context(cert, key, client_ca=ca, crl_file=crl), echo_handler).start()
            good = try_roundtrip(tls13.client_context(ca, ccert, ckey), srv.port)
            revoked = try_roundtrip(tls13.client_context(ca, bcert, bkey), srv.port)
            srv.close()
            srv2 = tls13.TlsServer(tls13.server_context(cert, key, client_ca=ca), echo_handler).start()
            without = try_roundtrip(tls13.client_context(ca, bcert, bkey), srv2.port)   # sin CRL el revocado entraba: por eso existe el parámetro
            srv2.close()
            return {"good": good, "revoked": revoked, "without_crl": without}
        if name == "crl_args":
            out = {}
            crl = P.issue_crl(d, ck, cc, [], number=3)
            for label, fn in (("server_crl_without_client_ca", lambda: tls13.server_context(cert, key, crl_file=crl)),
                              ("client_min_without_crl", lambda: tls13.client_context(ca, min_crl_number=1)),
                              ("server_min_without_crl", lambda: tls13.server_context(cert, key, client_ca=ca, min_crl_number=1)),
                              ("client_rollback", lambda: tls13.client_context(ca, crl_file=crl, min_crl_number=4)),
                              ("server_rollback", lambda: tls13.server_context(cert, key, client_ca=ca, crl_file=crl, min_crl_number=4)),
                              ("client_ok", lambda: tls13.client_context(ca, crl_file=crl, min_crl_number=3)),
                              ("server_min_without_mtls", lambda: tls13.server_context(cert, key, min_crl_number=1)),
                              ("bad_limits", lambda: tls13.TlsServer(tls13.server_context(cert, key), echo_handler, max_connections=0)),
                              ("bad_origin_limit", lambda: tls13.TlsServer(tls13.server_context(cert, key), echo_handler, max_per_origin=0)),
                              ("bad_handshake_timeout", lambda: tls13.TlsServer(tls13.server_context(cert, key), echo_handler, handshake_timeout=0)),
                              ("bad_lifetime", lambda: tls13.TlsServer(tls13.server_context(cert, key), echo_handler, max_lifetime=0))):
                try:
                    fn()
                    out[label] = "ok"
                except Exception as exc:  # noqa: BLE001
                    out[label] = type(exc).__name__
            return out
    raise SystemExit(f"escenario desconocido: {name}")


if __name__ == "__main__":
    print(json.dumps(run(sys.argv[1])))
