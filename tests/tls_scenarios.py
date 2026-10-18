"""Escenarios TLS ejecutados en un PROCESO NUEVO (no es un archivo de pruebas de pytest).

La configuración de OpenSSL solo se aplica si `qce.transport.tls13` se importa antes que `cryptography`; por eso cada escenario
corre en su propio intérprete, igual que lo haría un servicio real arrancado con `child_env()`.
Uso: python tests/tls_scenarios.py <escenario> [argumentos]  →  imprime un JSON.
"""
import json
import sys

MODE = sys.argv[1] if len(sys.argv) > 1 else ""
if MODE == "misconfigured":
    import cryptography.x509  # noqa: F401  (importarlo ANTES inutiliza la configuración: el módulo debe fallar cerrado)

import datetime as dt  # noqa: E402
import ssl  # noqa: E402
import tempfile  # noqa: E402
import time  # noqa: E402
from pathlib import Path  # noqa: E402

from qce.transport import tls13  # noqa: E402


def echo_handler(conn, peer):
    tls13.send_frame(conn, tls13.recv_frame(conn)[::-1])


def pki(d, **leaf):
    from qce.transport import pki as P
    ca, ck, cc = P.issue_ca(d)
    cert, key = P.issue_leaf(d, ck, cc, "localhost", server=True, **leaf)
    return P, ca, ck, cc, cert, key


def try_connect(ctx, port, hostname="localhost", send=True):
    try:
        c = tls13.connect(ctx, "127.0.0.1", port, hostname, timeout=5)
        if send:
            tls13.send_frame(c, b"ping")
            tls13.recv_frame(c)  # en TLS 1.3 el rechazo del certificado de cliente aparece al leer
        info = {"ok": True, "version": c.version(), "cipher": c.cipher()[0]}
        c.close()
        return info
    except (ssl.SSLError, OSError, tls13.MalformedMessage) as exc:
        return {"ok": False, "error": type(exc).__name__}


def run(name, args):
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        if name == "attest":
            tls13.require_hybrid_only()
            return {"attested": True}
        if name == "misconfigured":
            try:
                tls13.require_hybrid_only()
                return {"raised": False}
            except tls13.TransportMisconfigured as exc:
                return {"raised": True, "mentions_import_order": "cryptography" in str(exc)}
        P, ca, ck, cc, cert, key = pki(d)
        if name == "echo":
            srv = tls13.TlsServer(tls13.server_context(cert, key), echo_handler).start()
            c = tls13.connect(tls13.client_context(ca), "127.0.0.1", srv.port, "localhost")
            tls13.send_frame(c, b"hola poscuantico")
            out = {"version": c.version(), "cipher": c.cipher()[0], "echo": tls13.recv_frame(c).decode()}
            c.close(); srv.close()
            return out
        if name == "context_properties":
            s, c = tls13.server_context(cert, key), tls13.client_context(ca)
            return {"server_tickets": s.num_tickets, "server_min": s.minimum_version.name, "client_min": c.minimum_version.name,
                    "client_verify": c.verify_mode.name, "client_hostname_check": c.check_hostname, "server_verify": s.verify_mode.name}
        if name == "wrong_hostname":
            srv = tls13.TlsServer(tls13.server_context(cert, key), echo_handler).start()
            return try_connect(tls13.client_context(ca), srv.port, hostname="otro.example")
        if name == "untrusted_ca":
            ca2, *_ = P.issue_ca(d / "x") if (d / "x").mkdir() is None else (None,)
            srv = tls13.TlsServer(tls13.server_context(cert, key), echo_handler).start()
            return try_connect(tls13.client_context(ca2), srv.port)
        if name == "expired":
            cert2, key2 = P.issue_leaf(d, ck, cc, "caducado", server=True, days=1, not_before_offset=dt.timedelta(days=-3))
            srv = tls13.TlsServer(tls13.server_context(cert2, key2), echo_handler).start()
            return try_connect(tls13.client_context(ca), srv.port, hostname="caducado")
        if name in ("mtls_missing", "mtls_ok"):
            seen = []
            srv = tls13.TlsServer(tls13.server_context(cert, key, client_ca=ca),
                                  lambda c, peer: (seen.append(peer["subject"][0][0][1]), echo_handler(c, peer))).start()
            if name == "mtls_ok":
                ccert, ckey = P.issue_leaf(d, ck, cc, "cliente-1", server=False)
                r = try_connect(tls13.client_context(ca, ccert, ckey), srv.port)
            else:
                r = try_connect(tls13.client_context(ca), srv.port)
            time.sleep(0.3)
            return {**r, "handler_saw": seen, "failed_handshakes": srv.failed_handshakes}
        if name == "tls12_client":
            srv = tls13.TlsServer(tls13.server_context(cert, key), echo_handler).start()
            c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); c.load_verify_locations(str(ca)); c.maximum_version = ssl.TLSVersion.TLSv1_2
            return try_connect(c, srv.port)
        if name == "classical_group_client":
            srv = tls13.TlsServer(tls13.server_context(cert, key), echo_handler).start()
            c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); c.load_verify_locations(str(ca)); c.set_ecdh_curve("prime256v1")
            return try_connect(c, srv.port)
        if name == "frames":
            out = {}
            for label, fn in (("send_too_big", lambda: tls13.send_frame(None, b"x" * (tls13.MAX_FRAME + 1))),):
                try:
                    fn(); out[label] = "sin error"
                except tls13.MalformedMessage:
                    out[label] = "MalformedMessage"
            def small_only(c, p):
                tls13.recv_frame(c, max_size=8)  # un mensaje mayor lanza MalformedMessage y cierra la conexión
                tls13.send_frame(c, b"OK")
            srv = tls13.TlsServer(tls13.server_context(cert, key), small_only).start()
            for label, payload in (("small", b"x" * 4), ("oversized", b"x" * 100)):
                c = tls13.connect(tls13.client_context(ca), "127.0.0.1", srv.port, "localhost")
                try:
                    tls13.send_frame(c, payload)
                    out[label + "_reply"] = tls13.recv_frame(c, max_size=8).decode()
                except (OSError, ssl.SSLError, tls13.MalformedMessage):
                    out[label + "_reply"] = None
                c.close()
            return out
        if name == "serve":  # para que un tercero (openssl s_client) confirme el grupo negociado
            srv = tls13.TlsServer(tls13.server_context(cert, key), echo_handler).start()
            (d / "ca.pem").write_bytes(Path(ca).read_bytes())
            print(json.dumps({"port": srv.port, "ca": str(ca)}), flush=True)
            time.sleep(float(args[0]) if args else 30)
            return {}
        if name == "mldsa":  # certificados ML-DSA-65 generados con el openssl del sistema (args: cert key)
            cert3, key3 = args
            srv = tls13.TlsServer(tls13.server_context(cert3, key3), echo_handler).start()
            return try_connect(tls13.client_context(cert3), srv.port)
    raise SystemExit(f"escenario desconocido: {name}")


if __name__ == "__main__":
    result = run(MODE, sys.argv[2:])
    if result:
        print(json.dumps(result))
