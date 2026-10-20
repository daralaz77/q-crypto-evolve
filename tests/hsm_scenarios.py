"""Escenarios del servidor TLS con la clave en un HSM (SoftHSM de prueba), cada uno en un PROCESO NUEVO con su propio token temporal.

Necesita: el proveedor PKCS#11 de OpenSSL compilado (`QCE_HSM_PROVIDER` o ~/.qce-hsm-lab/lib/pkcs11.dylib), `softhsm2-util`, `p11tool` (GnuTLS) y el `openssl` de OpenSSL 3.
Uso: python tests/hsm_scenarios.py <escenario> → imprime un JSON (última línea).
"""
import datetime as dt
import ipaddress
import json
import os
import pwd
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
from pathlib import Path


def find(name, extra=()):
    return shutil.which(name) or next((p for p in (*extra, f"/opt/homebrew/bin/{name}", f"/usr/local/bin/{name}", f"/opt/homebrew/opt/nss/bin/{name}", f"/usr/local/opt/nss/bin/{name}") if os.path.exists(p)), None)


HOME = Path(pwd.getpwuid(os.getuid()).pw_dir)
PROVIDER = Path(os.environ.get("QCE_HSM_PROVIDER", HOME / ".qce-hsm-lab" / "lib" / "pkcs11.dylib"))
SOFTHSM_MODULE = os.environ.get("QCE_SOFTHSM_MODULE", "/opt/homebrew/lib/softhsm/libsofthsm2.so")
OPENSSL = next((p for p in ("/opt/homebrew/opt/openssl@3/bin/openssl", "/usr/local/opt/openssl@3/bin/openssl") if os.path.exists(p)), find("openssl"))   # el openssl del sistema (LibreSSL) no sirve; con PATH mínimo `which` lo encontraría primero
TOOLS = {"softhsm2-util": find("softhsm2-util"), "p11tool": find("p11tool")}
AVAILABLE = PROVIDER.exists() and Path(SOFTHSM_MODULE).exists() and all(TOOLS.values()) and OPENSSL


QUIRKS = os.environ.get("QCE_HSM_QUIRKS", "pkcs11-module-quirks = no-deinit\n")   # ver docs/HSM.md: sin esto, cerrar el contexto y hacer fork() puede terminar en SIGSEGV


def setup(tmp: Path, label="qce-test"):
    """Token temporal con una clave RSA generada DENTRO, certificado de una CA temporal y configuración de proveedores. Devuelve rutas y la URI."""
    pin = secrets.token_hex(6)
    (tmp / "tokens").mkdir()
    (tmp / "pin").write_text(pin + "\n")
    (tmp / "pin").chmod(0o600)
    conf = tmp / "softhsm2.conf"
    conf.write_text(f"directories.tokendir = {tmp}/tokens\nobjectstore.backend = file\nlog.level = ERROR\n")
    os.environ["SOFTHSM2_CONF"] = str(conf)
    env = {**os.environ, "GNUTLS_PIN": pin}
    run = lambda *a, **k: subprocess.run(a, capture_output=True, text=True, env=env, timeout=60, **k)      # noqa: E731
    r = run(TOOLS["softhsm2-util"], "--init-token", "--free", "--label", label, "--so-pin", secrets.token_hex(6), "--pin", pin)
    assert "initialized" in r.stdout, r.stdout + r.stderr
    g = run(TOOLS["p11tool"], f"--provider={SOFTHSM_MODULE}", "--login", "--generate-privkey=rsa", "--bits=2048", "--label", "tls-key", "--id", "01", f"pkcs11:token={label}")
    assert "BEGIN PUBLIC KEY" in g.stdout + g.stderr, g.stderr
    pub = run(TOOLS["p11tool"], f"--provider={SOFTHSM_MODULE}", "--login", "--export", f"pkcs11:token={label};object=tls-key;type=public").stdout
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    from qce.transport import pki
    ca_path, ca_key, ca_cert = pki.issue_ca(tmp)
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])).issuer_name(ca_cert.subject)
            .public_key(serialization.load_pem_public_key(pub.encode())).serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(minutes=1))
            .not_valid_after(now + dt.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True).sign(ca_key, hashes.SHA256()))
    (tmp / "tls.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    cnf = tmp / "openssl-hsm.cnf"
    cnf.write_text(f"openssl_conf = i\n[i]\nproviders = ps\n[ps]\ndefault = d\npkcs11 = p\n[d]\nactivate = 1\n[p]\nmodule = {PROVIDER}\npkcs11-module-path = {SOFTHSM_MODULE}\n{QUIRKS}activate = 1\n")
    uri = f"pkcs11:token={label};object=tls-key;type=private?pin-source=file:{tmp}/pin"
    return {"conf": cnf, "cert": tmp / "tls.pem", "ca": ca_path, "uri": uri, "pin": pin, "label": label, "env": env, "run": run}


def client(port, ca, timeout=20, data=b"\x00\x00\x00\x02ab", groups="X25519MLKEM768"):
    out = subprocess.run([OPENSSL, "s_client", "-connect", f"127.0.0.1:{port}", "-tls1_3", "-groups", groups, "-CAfile", str(ca), "-servername", "localhost",
                          "-verify_hostname", "localhost"], input=data, capture_output=True, timeout=timeout)
    return (out.stdout + out.stderr).decode(errors="replace")


def serve_one(ctx, ls, res):
    raw, _ = ls.accept()
    try:
        c = ctx.accept(raw, timeout=10)
        res.append({"ok": True, "conn": (c.version, c.group, c.cipher)})
        c.send_frame(c.recv_frame()[::-1])
        c.close()
    except BaseException as e:   # noqa: BLE001
        res.append({"ok": False, "err": type(e).__name__, "msg": str(e)[:120]})
        raw.close()


def listener():
    ls = socket.socket()
    ls.bind(("127.0.0.1", 0))
    ls.listen(8)
    return ls, ls.getsockname()[1]


def sc_e2e():
    from qce.transport.hsm_tls import HsmServerContext
    with tempfile.TemporaryDirectory() as td:
        s = setup(Path(td))
        ctx = HsmServerContext(s["conf"], s["cert"], s["uri"])
        out = {"conexiones": []}
        for _ in range(4):                      # varias conexiones con el mismo contexto: cada una libera su referencia
            ls, port = listener()
            res = []
            t = threading.Thread(target=serve_one, args=(ctx, ls, res))
            t.start()
            txt = client(port, s["ca"])
            t.join(10)
            ls.close()
            out["conexiones"].append({"servidor": res[0] if res else None, "verificacion_ok": "Verification: OK" in txt,
                                      "grupo_cliente": "Negotiated TLS1.3 group: X25519MLKEM768" in txt, "firma": next((l.split(": ")[1] for l in txt.splitlines() if l.startswith("Peer signature type")), None),
                                      "protocolo": next((l.split(": ")[1] for l in txt.splitlines() if l.startswith("Protocol")), None)})
        # un cliente que no confía en la CA falla, y el contexto sigue sirviendo después
        other = Path(td) / "otra"
        other.mkdir()
        from qce.transport import pki
        other_ca, _, _ = pki.issue_ca(other)
        ls, port = listener(); res = []
        t = threading.Thread(target=serve_one, args=(ctx, ls, res)); t.start()
        txt = client(port, other_ca); t.join(10); ls.close()
        out["cliente_con_otra_ca"] = {"verificacion_ok": "Verification: OK" in txt, "servidor": res[0]["ok"] if res else None}
        ls, port = listener(); res = []
        t = threading.Thread(target=serve_one, args=(ctx, ls, res)); t.start()
        txt = client(port, s["ca"]); t.join(10); ls.close()
        out["despues_del_fallo"] = {"verificacion_ok": "Verification: OK" in txt, "servidor_ok": bool(res and res[0]["ok"])}
        ctx.close()
        return out


def sc_key_never_leaves():
    from qce.transport import hsm_tls as H, tls13_psk as P
    with tempfile.TemporaryDirectory() as td:
        s = setup(Path(td))
        ctx = H.HsmServerContext(s["conf"], s["cert"], s["uri"])
        ctx.close()
        out = {}
        r = s["run"](TOOLS["p11tool"], f"--provider={SOFTHSM_MODULE}", "--login", "--export", f"pkcs11:token={s['label']};object=tls-key;type=private")
        out["p11tool_exporta_privada"] = "BEGIN" in r.stdout
        listed = s["run"](TOOLS["p11tool"], f"--provider={SOFTHSM_MODULE}", "--login", "--list-all", f"pkcs11:token={s['label']}").stdout
        out["flags_privada"] = next((l.strip() for l in listed.splitlines() if "CKA_NEVER_EXTRACTABLE" in l), "")
        l, c = P._load()
        H._prepare(c)
        for f, args in (("rsa.pem", ["RSA", "-pkeyopt", "rsa_keygen_bits:2048"]), ("ec.pem", ["EC", "-pkeyopt", "ec_paramgen_curve:P-256"])):
            subprocess.run([OPENSSL, "genpkey", "-algorithm", *args, "-out", f"{td}/{f}"], capture_output=True)
            store = c.OSSL_STORE_open_ex(f"file:{td}/{f}".encode(), None, None, None, None, None, None, None)
            pk = None
            while not pk and not c.OSSL_STORE_eof(store):
                info = c.OSSL_STORE_load(store)
                if info and c.OSSL_STORE_INFO_get_type(info) == H.OSSL_STORE_INFO_PKEY:
                    pk = c.OSSL_STORE_INFO_get1_PKEY(info)
            out[f"software_{f.split('.')[0]}_exportable"] = H.key_is_extractable(c, pk)
        # el contexto se niega a usar una clave que el proceso pudiera leer
        orig = H.key_is_extractable
        H.key_is_extractable = lambda crypto, pkey: True
        try:
            H.HsmServerContext(s["conf"], s["cert"], s["uri"])
            out["clave_exportable_aceptada"] = True
        except Exception as e:  # noqa: BLE001
            out["clave_exportable_aceptada"] = False
            out["clave_exportable_error"] = type(e).__name__
        finally:
            H.key_is_extractable = orig
        # ningún archivo creado contiene la clave privada (ni el PIN en claro fuera del archivo de PIN)
        leaked = [str(p.relative_to(td)) for p in Path(td).rglob("*") if p.is_file() and p.name not in ("rsa.pem", "ec.pem") and b"PRIVATE KEY" in p.read_bytes()]
        out["archivos_con_clave_privada"] = leaked
        return out


def attempt(fn):
    try:
        fn()
        return "aceptado"
    except Exception as e:  # noqa: BLE001
        return f"{type(e).__name__}: {str(e)[:90]}"


def sc_refusals():
    from qce.transport import hsm_tls as H, pki
    from qce.core.errors import PolicyViolation
    with tempfile.TemporaryDirectory() as td:
        s = setup(Path(td))
        mk = lambda **k: H.HsmServerContext(*[k.get(n, s[n]) if n != "uri" else k.get("uri", s["uri"]) for n in ("conf", "cert", "uri")])      # noqa: E731
        out = {}
        out["base_ok"] = attempt(lambda: mk().close())
        out["uri_no_pkcs11"] = attempt(lambda: mk(uri=f"file:{td}/tls.pem"))
        out["uri_publica"] = attempt(lambda: mk(uri=s["uri"].replace("type=private", "type=public")))
        out["uri_sin_tipo"] = attempt(lambda: mk(uri=s["uri"].replace(";type=private", "")))
        out["objeto_inexistente"] = attempt(lambda: mk(uri=s["uri"].replace("object=tls-key", "object=no-existe")))
        out["token_inexistente"] = attempt(lambda: mk(uri=s["uri"].replace("token=qce-test", "token=otro")))
        out["config_inexistente"] = attempt(lambda: H.HsmServerContext(f"{td}/no.cnf", s["cert"], s["uri"]))
        out["cert_inexistente"] = attempt(lambda: H.HsmServerContext(s["conf"], f"{td}/no.pem", s["uri"]))
        bad = Path(td) / "sin_proveedor.cnf"
        bad.write_text(f"openssl_conf = i\n[i]\nproviders = ps\n[ps]\ndefault = d\n[d]\nactivate = 1\n")      # sin el proveedor PKCS#11: NO debe caer a software
        out["sin_proveedor_pkcs11"] = attempt(lambda: H.HsmServerContext(bad, s["cert"], s["uri"]))
        other = Path(td) / "otro"; other.mkdir()
        ca2, ck2, cc2 = pki.issue_ca(other)
        cert2, _key2 = pki.issue_leaf(other, ck2, cc2, "localhost", server=True)
        out["certificado_de_otra_clave"] = attempt(lambda: mk(cert=cert2))
        (Path(td) / "basura.pem").write_text("no soy un certificado\n")
        out["certificado_basura"] = attempt(lambda: mk(cert=Path(td) / "basura.pem"))
        out["suite_no_permitida"] = attempt(lambda: H.HsmServerContext(s["conf"], s["cert"], s["uri"], suite="otra"))
        out["grupo_no_permitido"] = attempt(lambda: H.HsmServerContext(s["conf"], s["cert"], s["uri"], group="X448"))
        return out


def sc_pin(variant):
    """El inicio de sesión de PKCS#11 es por token Y por proceso: una vez abierto, ningún contexto posterior vuelve a pedir el PIN. Por eso el rechazo se prueba como PRIMERA operación de un proceso nuevo."""
    from qce.transport import hsm_tls as H
    with tempfile.TemporaryDirectory() as td:
        s = setup(Path(td))
        (Path(td) / "pin_mala").write_text("000000\n")
        uri = {"equivocado": s["uri"].replace(f"{td}/pin", f"{td}/pin_mala"), "ausente": s["uri"].split("?")[0], "correcto": s["uri"]}[variant]
        r = attempt(lambda: H.HsmServerContext(s["conf"], s["cert"], uri).close())
        return {"resultado": r}


def sc_pin_wrong():
    return sc_pin("equivocado")


def sc_pin_missing():
    return sc_pin("ausente")


def sc_pin_ok():
    return sc_pin("correcto")


def sc_lifecycle():
    """Dos contextos sobre la misma configuración comparten el módulo PKCS#11; cerrarlos NO descarga el módulo (si se descargara, el siguiente fork terminaba en SIGSEGV: INC-0027)."""
    from qce.transport import hsm_tls as H
    with tempfile.TemporaryDirectory() as td:
        s = setup(Path(td))
        a = H.HsmServerContext(s["conf"], s["cert"], s["uri"])
        b = H.HsmServerContext(s["conf"], s["cert"], s["uri"])
        out = {"mismo_libctx": bool(a._libctx) and a._libctx == b._libctx and len(H._LIBCTX) == 1}      # el MISMO contexto de biblioteca, no solo el mismo diccionario
        a.close()
        a.close()   # cerrar dos veces no falla
        ls, port = listener(); res = []
        t = threading.Thread(target=serve_one, args=(b, ls, res)); t.start()
        out["b_sirve_tras_cerrar_a"] = "Verification: OK" in client(port, s["ca"]); t.join(10); ls.close()
        b.close()
        out["fork_tras_cerrar_todo"] = subprocess.run(["/usr/bin/true"], capture_output=True).returncode == 0
        c = H.HsmServerContext(s["conf"], s["cert"], s["uri"])      # se puede abrir otro contexto después de cerrar todos
        c.close()
        out["reabrir"] = True
        return out


def sc_attest():
    from qce.transport import hsm_tls as H, tls13_psk as P
    with tempfile.TemporaryDirectory() as td:
        s = setup(Path(td))
        ctx = H.HsmServerContext(s["conf"], s["cert"], s["uri"])
        P.PskTlsConnection.group = property(lambda self: "x25519")      # lo negociado ya no es lo exigido
        ls, port = listener(); res = []
        t = threading.Thread(target=serve_one, args=(ctx, ls, res)); t.start()
        client(port, s["ca"]); t.join(10); ls.close()
        return {"servidor": res[0] if res else None}


def sc_key_removed():
    from qce.transport.hsm_tls import HsmServerContext
    with tempfile.TemporaryDirectory() as td:
        s = setup(Path(td))
        ctx = HsmServerContext(s["conf"], s["cert"], s["uri"])
        ls, port = listener(); res = []
        t = threading.Thread(target=serve_one, args=(ctx, ls, res)); t.start()
        before = "Verification: OK" in client(port, s["ca"]); t.join(10); ls.close()
        d = s["run"](TOOLS["p11tool"], f"--provider={SOFTHSM_MODULE}", "--login", "--delete", f"pkcs11:token={s['label']};object=tls-key;type=private", "--batch")
        ls, port = listener(); res2 = []
        t = threading.Thread(target=serve_one, args=(ctx, ls, res2)); t.start()
        txt = client(port, s["ca"]); t.join(10); ls.close()
        out = {"antes_ok": before, "borrado_rc": d.returncode, "despues_verificacion_ok": "Verification: OK" in txt, "despues_servidor": res2[0] if res2 else None}
        ctx.close()
        out["contexto_nuevo"] = attempt(lambda: HsmServerContext(s["conf"], s["cert"], s["uri"]))
        return out


def sc_leaks():
    from qce.transport import hsm_tls as H, tls13_psk as P
    import collections
    real_ssl, real_crypto = P._load()
    H._prepare(real_crypto)   # los tipos de ctypes se fijan sobre las funciones REALES, no sobre los envoltorios del contador

    class Count:
        def __init__(self, real):
            self._r, self.n = real, collections.Counter()

        def __getattr__(self, name):
            fn = getattr(self._r, name)
            if name in ("SSL_CTX_new_ex", "SSL_CTX_new", "SSL_new", "OSSL_LIB_CTX_new"):
                def new(*a):
                    r = fn(*a)
                    self.n[name] += bool(r)
                    return r
                return new
            if name in ("SSL_CTX_free", "SSL_free", "OSSL_LIB_CTX_free", "SSL_CTX_up_ref"):
                def free(*a):
                    self.n[name] += bool(a[0])
                    return fn(*a)
                return free
            return fn
    cs, cc = Count(real_ssl), Count(real_crypto)
    P._lib_cache = (cs, cc)
    with tempfile.TemporaryDirectory() as td:
        s = setup(Path(td))
        ctx = H.HsmServerContext(s["conf"], s["cert"], s["uri"])
        for good in (True, True, False, True, False):
            ls, port = listener(); res = []
            t = threading.Thread(target=serve_one, args=(ctx, ls, res)); t.start()
            if good:
                client(port, s["ca"])
            else:   # un cliente que solo habla TLS 1.2: el servidor (TLS 1.3 obligatorio) lo rechaza
                subprocess.run([OPENSSL, "s_client", "-connect", f"127.0.0.1:{port}", "-tls1_2"], input=b"", capture_output=True, timeout=20)
            t.join(10); ls.close()
        ctx.close()
        n = cs.n
        return {"ctx_creados": n["SSL_CTX_new_ex"] + n["SSL_CTX_new"] + n["SSL_CTX_up_ref"], "ctx_liberados": n["SSL_CTX_free"], "ssl_creados": n["SSL_new"], "ssl_liberados": n["SSL_free"],
                "libctx_creados": cc.n["OSSL_LIB_CTX_new"], "libctx_liberados": cc.n["OSSL_LIB_CTX_free"]}


def sc_nss():
    """Mozilla NSS (segunda implementación del híbrido) como CLIENTE de nuestro servidor con la clave en el token: verifica la cadena y la firma hecha por el token."""
    from qce.transport import hsm_tls as H2
    certutil, tstclnt = find("certutil"), find("tstclnt")
    if not (certutil and tstclnt):
        return {"sin_nss": True}
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        s = setup(td)

        def db(name, trust_ca):
            d = td / name
            d.mkdir()
            subprocess.run([certutil, "-N", "-d", f"sql:{d}", "--empty-password"], check=True, capture_output=True, timeout=60)
            if trust_ca:
                subprocess.run([certutil, "-A", "-d", f"sql:{d}", "-n", "labca", "-t", "C,,", "-i", str(s["ca"])], check=True, capture_output=True, timeout=60)
            return f"sql:{d}"
        ctx = H2.HsmServerContext(s["conf"], s["cert"], s["uri"])
        out = {}
        for name, database, groups in (("hibrido_con_ca", db("a", True), "x25519mlkem768"), ("solo_clasico", db("b", True), "x25519"), ("sin_confiar_en_la_ca", db("c", False), "x25519mlkem768")):
            ls, port = listener(); res = []
            t = threading.Thread(target=serve_one, args=(ctx, ls, res)); t.start()
            r = subprocess.run([tstclnt, "-d", database, "-h", "127.0.0.1", "-p", str(port), "-V", "tls1.3:tls1.3", "-I", groups, "-v"], input=b"\x00\x00\x00\x04ping",
                               capture_output=True, timeout=30)
            t.join(15); ls.close()
            text = (r.stdout + r.stderr).decode(errors="replace")
            out[name] = {"servidor": res[0] if res else None, "grupo_nss": "Key Exchange Group: x25519mlkem768" in text, "respuesta": b"gnip" in r.stdout, "version_tls13": "SSL version 3.4" in text}
        ctx.close()
        return out


SCEN = {"lifecycle": sc_lifecycle, "attest": sc_attest, "pin_wrong": sc_pin_wrong, "pin_missing": sc_pin_missing, "pin_ok": sc_pin_ok, "e2e": sc_e2e, "key_never_leaves": sc_key_never_leaves, "refusals": sc_refusals, "key_removed": sc_key_removed, "leaks": sc_leaks, "nss": sc_nss}

if __name__ == "__main__":
    print(json.dumps(SCEN[sys.argv[1]]()))
