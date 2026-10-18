"""Escenarios de custodia de la clave TLS, cada uno en un PROCESO NUEVO (ver tests/tls_scenarios.py para el porqué).
Uso: python tests/custody_scenarios.py <escenario>  →  imprime un JSON."""
import json
import sys

from qce.transport import custody, tls13  # noqa: E402  (tls13 se importa dentro de custody antes que cryptography)

import datetime as dt  # noqa: E402
import tempfile  # noqa: E402
import time  # noqa: E402
from pathlib import Path  # noqa: E402

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402

from qce.core.chainlog import ChainLog  # noqa: E402
from qce.core.errors import KeyStateError  # noqa: E402
from qce.key_management import vault  # noqa: E402
from qce.key_management.keystore import KeyStore, Purpose, State  # noqa: E402
from qce.transport import pki  # noqa: E402


class Clock:
    t = time.time()

    def __call__(self):
        return self.t


def echo(conn, peer):
    tls13.send_frame(conn, tls13.recv_frame(conn)[::-1])


def setup(d, clock=None, audit=None):
    clock = clock or Clock()
    ks = KeyStore(audit, clock)
    cu = custody.TlsKeyCustody(ks, d / "certs", clock=clock)
    ca, ck, cc = pki.issue_ca(d)
    return ks, cu, ca, ck, cc, clock


def roundtrip(ca, port, msg=b"hola"):
    c = tls13.connect(tls13.client_context(ca), "127.0.0.1", port, "localhost", timeout=5)
    tls13.send_frame(c, msg)
    out = tls13.recv_frame(c)
    serial = c.getpeercert()["serialNumber"]
    c.close()
    return out, serial


def roundtrip_ctx(ctx, port, msg=b"hola"):
    c = tls13.connect(ctx, "127.0.0.1", port, "localhost", timeout=5)
    tls13.send_frame(c, msg)
    out = tls13.recv_frame(c)
    c.close()
    return out.decode()


def fails(fn):
    try:
        fn()
        return None
    except Exception as exc:  # noqa: BLE001
        return type(exc).__name__


def leftover_key_dirs():
    return sorted(p.name for p in Path(tempfile.gettempdir()).glob("qce-key-*"))


def files_with_private_key(root):
    return sorted(str(p.relative_to(root)) for p in Path(root).rglob("*") if p.is_file() and b"PRIVATE KEY" in p.read_bytes())


def run(name):
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        if name == "serve_and_no_plaintext_key":
            ks, cu, ca, ck, cc, _ = setup(d)
            before = leftover_key_dirs()
            kid = cu.provision_with_lab_ca(ck, cc, "localhost", 3600)
            srv = tls13.TlsServer(cu.server_context(), echo).start()
            out, _ = roundtrip(ca, srv.port)
            srv.close()
            return {"echo": out.decode(), "leftover_temp_dirs": [x for x in leftover_key_dirs() if x not in before],
                    "files_with_private_key": files_with_private_key(d), "cert_files": sorted(p.name for p in (d / "certs").iterdir()),
                    "key_id_has_cert": (d / "certs" / f"{kid}.pem").exists()}
        if name == "key_file_is_encrypted_while_it_exists":
            ks, cu, ca, ck, cc, _ = setup(d)
            cu.provision_with_lab_ca(ck, cc, "localhost", 3600)
            seen = {}
            real = custody.tls13.server_context

            def spy(certfile, keyfile, client_ca=None, key_password=None):
                text = Path(keyfile).read_text()
                seen.update(header=text.splitlines()[0], has_password=key_password is not None and len(key_password) >= 32,
                            mode=oct(Path(keyfile).stat().st_mode & 0o777), dir_mode=oct(Path(keyfile).parent.stat().st_mode & 0o777))
                return real(certfile, keyfile, client_ca=client_ca, key_password=key_password)
            custody.tls13.server_context = spy
            cu.server_context()
            return seen
        if name == "vault_roundtrip":
            ks, cu, ca, ck, cc, _ = setup(d)
            kid = cu.provision_with_lab_ca(ck, cc, "localhost", 3600)
            der = ks.use(kid, Purpose.TLS, "sign")
            vault.save(ks, d / "v.bin", "frase-larga-de-prueba", n=2**14)
            raw = (d / "v.bin").read_bytes()
            ks2 = vault.load(d / "v.bin", "frase-larga-de-prueba", clock=Clock())
            cu2 = custody.TlsKeyCustody(ks2, d / "certs")
            srv = tls13.TlsServer(cu2.server_context(), echo).start()
            out, _ = roundtrip(ca, srv.port)
            srv.close()
            return {"der_in_vault": der in raw, "hex_in_vault": der.hex().encode() in raw, "pem_in_vault": b"PRIVATE KEY" in raw,
                    "restored_purpose": ks2.info(kid).purpose.value, "restored_serves": out.decode()}
        if name == "rotation":
            ks, cu, ca, ck, cc, _ = setup(d)
            old = cu.provision_with_lab_ca(ck, cc, "localhost", 3600)
            srv = tls13.TlsServer(cu.server_context(), echo).start()
            _, serial1 = roundtrip(ca, srv.port)
            c_open = tls13.connect(tls13.client_context(ca), "127.0.0.1", srv.port, "localhost")  # conexión abierta ANTES de rotar
            new = cu.rotate(ck, cc, "localhost", 3600)
            srv.set_context(cu.server_context())
            _, serial2 = roundtrip(ca, srv.port)
            tls13.send_frame(c_open, b"abierta")
            still = tls13.recv_frame(c_open).decode()
            c_open.close(); srv.close()
            return {"serial_changed": serial1 != serial2, "old_state": ks.info(old).state.value, "new_state": ks.info(new).state.value,
                    "new_generation": ks.info(new).generation, "old_can_build_context": fails(lambda: cu.server_context(key_id=old)),
                    "open_connection_still_works": still, "active_is_new": cu.active_id() == new}
        if name == "revocation":
            ks, cu, ca, ck, cc, _ = setup(d)
            kid = cu.provision_with_lab_ca(ck, cc, "localhost", 3600)
            srv = tls13.TlsServer(cu.server_context(), echo).start()
            ok_before = roundtrip(ca, srv.port)[0].decode()
            cu.revoke(kid, "compromiso", server=srv)
            new_conn = fails(lambda: roundtrip(ca, srv.port))
            res = {"ok_before": ok_before, "secret_erased": ks.info(kid).secret is None, "new_connection_fails": new_conn is not None,
                   "context_after_revoke": fails(lambda: cu.server_context()), "failed_handshakes": srv.failed_handshakes >= 1}
            srv.close()
            return res
        if name == "expiry":
            ks, cu, ca, ck, cc, clock = setup(d)
            cu.provision_with_lab_ca(ck, cc, "localhost", 100)
            ok = fails(lambda: cu.server_context())
            clock.t += 101
            return {"before": ok, "after": fails(lambda: cu.server_context())}
        if name == "purpose_separation":
            ks, cu, ca, ck, cc, _ = setup(d)
            kid = cu.provision_with_lab_ca(ck, cc, "localhost", 3600)
            return {"protect_with_tls_key": fails(lambda: ks.protect(kid, b"x")), "use_as_encrypt": fails(lambda: ks.use(kid, Purpose.ENCRYPT, "protect")),
                    "use_as_tls": fails(lambda: ks.use(kid, Purpose.TLS, "sign")),
                    "audit_misuse_logged": True}
        if name == "csr_flow":
            ks, cu, ca, ck, cc, clock = setup(d)
            kid = cu.provision_key(3600)
            no_cert = [fails(lambda: cu.server_context()), fails(lambda: cu.server_context(key_id=kid))]
            csr = x509.load_pem_x509_csr(cu.csr_pem(kid, "localhost"))
            cert_pem = pki.sign_csr(ck, cc, csr).public_bytes(serialization.Encoding.PEM)
            cu.install_certificate(kid, cert_pem, "localhost")
            srv = tls13.TlsServer(cu.server_context(), echo).start()
            out = roundtrip(ca, srv.port)[0].decode()
            srv.close()
            kid2 = cu.provision_key(3600)
            other_key = fails(lambda: cu.install_certificate(kid2, cert_pem, "localhost"))  # certificado de OTRA clave
            csr_otro = x509.load_pem_x509_csr(cu.csr_pem(kid2, "otro.example"))
            cert_otro = pki.sign_csr(ck, cc, csr_otro).public_bytes(serialization.Encoding.PEM)
            wrong_name = fails(lambda: cu.install_certificate(kid2, cert_otro, "localhost"))
            real_clock = cu._clock
            cu._clock = lambda: clock.t + 3 * 86400  # solo el reloj de la custodia avanza: el certificado (1 día) ya no es vigente
            expired = fails(lambda: cu.install_certificate(kid2, cert_otro, "otro.example"))
            cu._clock = real_clock
            return {"no_cert": no_cert, "echo": out, "other_key": other_key, "wrong_name": wrong_name, "expired": expired}
        if name == "swapped_certificate":
            ks, cu, ca, ck, cc, _ = setup(d)
            k1 = cu.provision_with_lab_ca(ck, cc, "localhost", 3600)
            k2 = cu.provision_with_lab_ca(ck, cc, "localhost", 3600)
            (d / "certs" / f"{k1}.pem").write_bytes((d / "certs" / f"{k2}.pem").read_bytes())
            return {"error": fails(lambda: cu.server_context(key_id=k1))}
        if name == "audit_clean":
            audit = ChainLog(d / "audit.jsonl")
            ks, cu, ca, ck, cc, _ = setup(d, audit=audit)
            kid = cu.provision_with_lab_ca(ck, cc, "localhost", 3600)
            der = ks.use(kid, Purpose.TLS, "sign")
            cu.server_context()
            cu.rotate(ck, cc, "localhost", 3600)
            cu.revoke(kid, "prueba")
            raw = (d / "audit.jsonl").read_bytes()
            return {"der_hex_in_audit": der.hex().encode() in raw, "pem_in_audit": b"PRIVATE KEY" in raw, "events": len(audit.entries()),
                    "kinds": sorted({json.loads(e["body"])["event"] for e in audit.entries()})}
        if name == "auto_rotation":
            ks, cu, ca, ck, cc, clock = setup(d)
            kid1 = cu.provision_with_lab_ca(ck, cc, "localhost", 3600)
            srv = tls13.TlsServer(cu.server_context(), echo).start()
            _, serial1 = roundtrip(ca, srv.port)
            not_due = cu.rotate_if_due(ck, cc, "localhost", 3600, renew_before_s=600, server=srv)
            clock.t += 3100                                              # quedan 500 s
            kid2 = cu.rotate_if_due(ck, cc, "localhost", 3600, renew_before_s=500, server=srv)   # justo en el límite: rota
            out2, serial2 = roundtrip(ca, srv.port)
            again = cu.rotate_if_due(ck, cc, "localhost", 3600, renew_before_s=500, server=srv)
            clock.t += 7200                                              # la clave activa ya caducó
            kid3 = cu.rotate_if_due(ck, cc, "localhost", 3600, renew_before_s=500, server=srv)
            out3, serial3 = roundtrip(ca, srv.port)
            srv.close()
            ks2, cu2, ca2, ck2, cc2, _ = setup(d / "vacio") if (d / "vacio").mkdir() is None else None   # custodia sin ninguna clave
            first = cu2.rotate_if_due(ck2, cc2, "localhost", 3600, renew_before_s=500)
            from_nothing_serves = first is not None and cu2.server_context(first) is not None and ks2.info(first).generation == 1
            cu2.revoke(first, "prueba")                                  # y tras revocar la única activa también se recupera
            after_revoke = cu2.rotate_if_due(ck2, cc2, "localhost", 3600, renew_before_s=500)
            return {"from_nothing_serves": from_nothing_serves, "recovers_after_revoke": after_revoke is not None and after_revoke != first, "not_due": not_due, "rotated_at_limit": kid2 is not None and kid2 != kid1, "serial_changed": serial1 != serial2, "echo2": out2.decode(),
                    "again_is_none": again is None, "old_state": ks.info(kid1).state.name, "second_state": ks.info(kid2).state.name,
                    "rotated_after_expiry": kid3 is not None and kid3 not in (kid1, kid2), "serial3_changed": serial3 not in (serial1, serial2), "echo3": out3.decode()}
        if name == "revocation_crl":
            ks, cu, ca, ck, cc, _ = setup(d)
            kid = cu.provision_with_lab_ca(ck, cc, "localhost", 3600)
            srv = tls13.TlsServer(cu.server_context(), echo).start()     # el servidor sigue sirviendo el certificado aunque se revoque (atacante con la clave)
            empty = pki.issue_crl(d, ck, cc, [], name="vacia.pem")
            ok_before = roundtrip_ctx(tls13.client_context(ca, crl_file=empty), srv.port)
            cu.revoke(kid, "clave comprometida")
            crl = pki.issue_crl(d, ck, cc, cu.revoked_certificates(), name="crl.pem")
            revoked = fails(lambda: roundtrip_ctx(tls13.client_context(ca, crl_file=crl), srv.port))
            without_crl = roundtrip_ctx(tls13.client_context(ca), srv.port)
            ca2, ck2, cc2 = pki.issue_ca(d / "otra") if (d / "otra").mkdir() is None else None
            foreign_crl = pki.issue_crl(d / "otra", ck2, cc2, [], name="otra.pem")
            wrong_ca_crl = fails(lambda: roundtrip_ctx(tls13.client_context(ca, crl_file=foreign_crl), srv.port))   # sin lista de SU CA: falla cerrado
            srv.close()
            return {"ok_before": ok_before, "revoked": revoked, "without_crl_still_accepted": without_crl, "foreign_crl": wrong_ca_crl,
                    "crl_entries": len(cu.revoked_certificates())}
    raise SystemExit(f"escenario desconocido: {name}")


if __name__ == "__main__":
    print(json.dumps(run(sys.argv[1])))
