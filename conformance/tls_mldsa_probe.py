"""B1 de docs/COMPARATIVA_PQC.md: ¿funciona la AUTENTICACIÓN poscuántica en TLS 1.3 con las herramientas que ya tenemos, y cuánto cuesta en bytes?

Genera una CA y un certificado de servidor ECDSA P-256 (como el PKI actual del transporte) y otros con ML-DSA-65 / ML-DSA-87 usando el `openssl` del sistema,
abre un apretón TLS 1.3 con `openssl s_server`/`s_client` (grupo X25519MLKEM768) y mide los mensajes del servidor con `-msg`; después repite el apretón con el
módulo `ssl` de Python (el que usa `qce.transport`). Todo en un directorio temporal; no toca `qce/` ni `tests/`.

  python conformance/tls_mldsa_probe.py        # imprime JSON; sale con 1 si algún apretón con certificados ML-DSA falla"""
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
from pathlib import Path

CLI = shutil.which("openssl")
ENV = {"PATH": os.environ.get("PATH", ""), "OPENSSL_CONF": "/dev/null"}


def sh(*a, cwd):
    subprocess.run([CLI, *a], cwd=cwd, check=True, capture_output=True, env=ENV, timeout=120)


def make_pki(d: Path, alg: str) -> None:
    gen = ["-algorithm", alg] if alg != "EC" else ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"]
    sh("genpkey", *gen, "-out", "ca.key", cwd=d)
    sh("req", "-x509", "-new", "-key", "ca.key", "-subj", "/CN=Lab CA", "-days", "1", "-out", "ca.pem",
       "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign", cwd=d)
    sh("genpkey", *gen, "-out", "srv.key", cwd=d)
    sh("req", "-new", "-key", "srv.key", "-subj", "/CN=localhost", "-out", "srv.csr", cwd=d)
    (d / "ext.cnf").write_text("subjectAltName=DNS:localhost,IP:127.0.0.1\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n", encoding="utf-8")
    sh("x509", "-req", "-in", "srv.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-days", "1", "-out", "srv.pem", "-extfile", "ext.cnf", cwd=d)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def cli_handshake(d: Path) -> dict:
    port = free_port()
    srv = subprocess.Popen([CLI, "s_server", "-accept", str(port), "-cert", "srv.pem", "-key", "srv.key", "-tls1_3", "-groups", "X25519MLKEM768", "-www"],
                           cwd=d, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=ENV)
    try:
        import time
        time.sleep(1.0)
        r = subprocess.run([CLI, "s_client", "-connect", f"127.0.0.1:{port}", "-servername", "localhost", "-CAfile", "ca.pem", "-verify_return_error", "-tls1_3",
                            "-groups", "X25519MLKEM768", "-msg"], cwd=d, input=b"", capture_output=True, timeout=20, env=ENV)
        out = (r.stdout + r.stderr).decode("utf-8", "replace")
    finally:
        srv.kill()
        srv.wait(5)
    lens = {}
    for m in re.finditer(r"<<<\s+TLS 1\.3, (?:Handshake|Handshake) \[length ([0-9a-f]+)\], (\w+)", out):
        lens[m.group(2)] = lens.get(m.group(2), 0) + int(m.group(1), 16)
    verify = re.search(r"Verification: (\w+)|Verify return code: (\d+)", out)
    return {"ok": "Verification: OK" in out or "Verify return code: 0" in out, "firma_de_par": (re.search(r"Peer signature type: (\S+)", out) or [None, None])[1],
            "grupo": (re.search(r"Negotiated TLS1.3 group: (\S+)|Server Temp Key: (\S+)", out) or [None])[0], "bytes_mensajes_servidor": lens,
            "total_bytes_mensajes_servidor": sum(lens.values())}


def python_ssl_handshake(d: Path) -> dict:
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.minimum_version = ssl.TLSVersion.TLSv1_3
    sctx.load_cert_chain(str(d / "srv.pem"), str(d / "srv.key"))
    cctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    cctx.minimum_version = ssl.TLSVersion.TLSv1_3
    cctx.load_verify_locations(str(d / "ca.pem"))
    ls = socket.socket()
    ls.bind(("127.0.0.1", 0))
    ls.listen(1)
    res = {"servidor": None}

    def serve():
        try:
            c, _ = ls.accept()
            with sctx.wrap_socket(c, server_side=True) as s:
                s.recv(1)
                s.sendall(b"x")
            res["servidor"] = "ok"
        except Exception as e:  # noqa: BLE001
            res["servidor"] = repr(e)[:120]
    t = threading.Thread(target=serve, daemon=True)
    t.start()
    try:
        with cctx.wrap_socket(socket.create_connection(("127.0.0.1", ls.getsockname()[1]), timeout=8), server_hostname="localhost") as c:
            c.sendall(b"y")
            c.recv(1)
            res.update(ok=True, version=c.version(), cifrado=c.cipher()[0])
    except Exception as e:  # noqa: BLE001
        res.update(ok=False, error=repr(e)[:160])
    t.join(5)
    ls.close()
    return res


def main() -> int:
    report = {"openssl_cli": subprocess.run([CLI, "version"], capture_output=True, text=True, timeout=30).stdout.strip(), "ssl_de_python": ssl.OPENSSL_VERSION, "casos": {}}
    ok = True
    for alg in ("EC", "ML-DSA-65", "ML-DSA-87"):
        with tempfile.TemporaryDirectory(prefix="qce-mldsa-") as td:
            d = Path(td)
            case = {}
            try:
                make_pki(d, alg)
                der = subprocess.run([CLI, "x509", "-in", "srv.pem", "-outform", "DER"], cwd=d, capture_output=True, env=ENV, timeout=120).stdout
                case["certificado_servidor_der_bytes"] = len(der)
                case["openssl_s_client"] = cli_handshake(d)
                case["python_ssl"] = python_ssl_handshake(d)
            except Exception as e:  # noqa: BLE001
                case["error"] = repr(e)[:200]
            report["casos"][alg] = case
            if alg != "EC":
                ok &= bool(case.get("openssl_s_client", {}).get("ok")) and bool(case.get("python_ssl", {}).get("ok"))
    report["ok"] = ok
    print(json.dumps(report, indent=1, ensure_ascii=False))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
