"""Escenarios EXPERIMENTALES de autenticación ML-DSA en el transporte TLS 1.3, cada uno en un PROCESO NUEVO (ver tests/tls_scenarios.py para el porqué).
Uso: python tests/mldsa_scenarios.py <escenario> <algoritmo>  →  imprime un JSON."""
import json
import sys

from qce.transport import custody, tls13  # noqa: E402  (tls13 va antes que cryptography)

import datetime as dt  # noqa: E402
import ssl  # noqa: E402
import tempfile  # noqa: E402
import time  # noqa: E402
from pathlib import Path  # noqa: E402

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402

from qce.key_management.keystore import KeyStore  # noqa: E402
from qce.transport import pki  # noqa: E402


def echo(conn, peer):
    tls13.send_frame(conn, tls13.recv_frame(conn)[::-1])


def try_connect(ctx, port, name="localhost"):
    try:
        c = tls13.connect(ctx, "127.0.0.1", port, name, timeout=5)
        tls13.send_frame(c, b"ping")
        out = tls13.recv_frame(c)  # el rechazo del certificado de cliente aparece al leer
        info = {"ok": out == b"gnip", "version": c.version(), "cipher": c.cipher()[0]}
        c.close()
        return info
    except (ssl.SSLError, OSError, tls13.MalformedMessage) as exc:
        return {"ok": False, "error": type(exc).__name__}


def cert_info(path):
    c = x509.load_pem_x509_certificate(Path(path).read_bytes())
    return {"der_bytes": len(c.public_bytes(serialization.Encoding.DER)), "signature_oid": c.signature_algorithm_oid.dotted_string}


def run(name, alg):
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        ca, ck, cc = pki.issue_ca(d, algorithm=alg)
        cert, key = pki.issue_leaf(d, ck, cc, "localhost", server=True, algorithm=alg)
        if name == "handshake":
            srv = tls13.TlsServer(tls13.server_context(cert, key), echo).start()
            out = try_connect(tls13.client_context(ca), srv.port)
            srv.close()
            return {**out, **cert_info(cert)}
        if name == "wrong_ca":
            other, _, _ = pki.issue_ca(Path(tempfile.mkdtemp(dir=d)), algorithm=alg)
            srv = tls13.TlsServer(tls13.server_context(cert, key), echo).start()
            out = try_connect(tls13.client_context(other), srv.port)
            srv.close()
            return out
        if name == "wrong_name":
            srv = tls13.TlsServer(tls13.server_context(cert, key), echo).start()
            out = try_connect(tls13.client_context(ca), srv.port, name="otro.example")
            srv.close()
            return out
        if name == "mutual":
            ccert, ckey = pki.issue_leaf(d, ck, cc, "cliente", server=False, algorithm=alg)
            srv = tls13.TlsServer(tls13.server_context(cert, key, client_ca=ca), echo).start()
            with_cert = try_connect(tls13.client_context(ca, ccert, ckey), srv.port)
            without = try_connect(tls13.client_context(ca), srv.port)
            srv.close()
            return {"with_client_cert": with_cert, "without_client_cert": without}
        if name == "crl":
            leaf = x509.load_pem_x509_certificate(cert.read_bytes())
            revoked = pki.issue_crl(d, ck, cc, [leaf], name="revoked.pem")
            empty = pki.issue_crl(d, ck, cc, [], name="empty.pem")
            srv = tls13.TlsServer(tls13.server_context(cert, key), echo).start()
            out = {"revoked": try_connect(tls13.client_context(ca, crl_file=revoked), srv.port), "not_revoked": try_connect(tls13.client_context(ca, crl_file=empty), srv.port)}
            srv.close()
            return out
        if name == "custody":
            ks = KeyStore(None, time.time)
            cu = custody.TlsKeyCustody(ks, d / "certs")
            kid = cu.provision_with_lab_ca(ck, cc, "localhost", 3600, algorithm=alg)
            srv = tls13.TlsServer(cu.server_context(), echo).start()
            out = try_connect(tls13.client_context(ca), srv.port)
            srv.close()
            leaked = sorted(str(p.relative_to(d)) for p in d.rglob("*") if p.is_file() and b"PRIVATE KEY" in p.read_bytes() and p.name not in (key.name, "ca.key"))
            return {**out, "files_with_private_key_besides_the_lab_leaf": leaked, "kid_has_cert": (d / "certs" / f"{kid}.pem").exists()}
        raise SystemExit(f"escenario desconocido: {name}")


if __name__ == "__main__":
    print(json.dumps(run(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else "ml-dsa-65")))
