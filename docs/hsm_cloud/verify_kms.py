"""Verificador del servidor TLS con la clave en un HSM por PKCS#11 REAL (p. ej. Google Cloud KMS con protección HSM). NO PROBADO contra Google: solo contra SoftHSM (--selftest-softhsm).

Qué comprueba (cada punto es una pregunta abierta que la guía de la biblioteca no responde):
  1. la clave del token NO es exportable y se carga por su URI (lo hace HsmServerContext y falla cerrado si no);
  2. un cliente `openssl s_client` (OpenSSL >= 3.5) completa TLS 1.3 con X25519MLKEM768 y VERIFICA el certificado cuya clave vive en el HSM;
  3. qué algoritmo de firma se usó (¿rsa_pss_rsae_sha256? ¿ecdsa?), para ver si la clave pública de Cloud KMS sirve como certificado TLS;
  4. latencia por apretón (cada firma pasa por la red);
  5. que cerrar los contextos y hacer fork() no cuelga ni mata el proceso (INC-0027) con ESTE módulo.
Imprime una línea JSON. No modifica nada del HSM: solo firma. Uso en la VM:
  KMS_PKCS11_CONFIG=kmsp11.yaml QCE_LIBSSL=<libssl.so.3 >= 3.5> python docs/hsm_cloud/verify_kms.py --config openssl-kms.cnf --cert tls.pem --ca ca.pem \\
      --uri 'pkcs11:token=qce-lab;object=qce-tls;type=private' [--openssl /ruta/openssl] [--n 20]
"""
import argparse
import json
import os
import re
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))


def one_connection(ctx, openssl, ca, results, timings):
    ls = socket.socket()
    ls.bind(("127.0.0.1", 0))
    ls.listen(4)
    port = ls.getsockname()[1]
    out = {}

    def serve():
        raw, _ = ls.accept()
        try:
            c = ctx.accept(raw, timeout=20)
            out["servidor"] = {"ok": True, "conn": [c.version, c.group, c.cipher]}
            c.send_frame(c.recv_frame()[::-1])
            c.close()
        except BaseException as exc:   # noqa: BLE001
            out["servidor"] = {"ok": False, "err": type(exc).__name__, "msg": str(exc)[:160]}
            raw.close()
    t = threading.Thread(target=serve)
    t.start()
    t0 = time.perf_counter()
    r = subprocess.run([openssl, "s_client", "-connect", f"127.0.0.1:{port}", "-tls1_3", "-groups", "X25519MLKEM768", "-CAfile", str(ca), "-servername", "localhost",
                        "-verify_hostname", "localhost"], input=b"\x00\x00\x00\x02ab", capture_output=True, timeout=60)
    timings.append((time.perf_counter() - t0) * 1000)
    t.join(30)
    ls.close()
    text = (r.stdout + r.stderr).decode(errors="replace")
    sig = re.search(r"Peer signature type: (\S+)", text)
    results.append({"servidor": out.get("servidor"), "verificacion_ok": "Verification: OK" in text,
                    "firma": sig.group(1) if sig else None, "grupo_cliente": bool(re.search(r"X25519MLKEM768", text))})


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config"); ap.add_argument("--cert"); ap.add_argument("--ca"); ap.add_argument("--uri")
    ap.add_argument("--openssl", default="openssl"); ap.add_argument("--n", type=int, default=10)
    ap.add_argument("--selftest-softhsm", action="store_true", help="usa un token SoftHSM temporal (solo para probar este script en el Mac del laboratorio)")
    a = ap.parse_args()
    cleanup = None
    if a.selftest_softhsm:
        import hsm_scenarios as H
        cleanup = tempfile.TemporaryDirectory()
        s = H.setup(Path(cleanup.name))
        a.config, a.cert, a.ca, a.uri = str(s["conf"]), str(s["cert"]), str(s["ca"]), s["uri"]
        a.openssl = H.OPENSSL
    if not all((a.config, a.cert, a.ca, a.uri)):
        ap.error("faltan --config, --cert, --ca y --uri (o --selftest-softhsm)")
    from qce.transport import hsm_tls
    summary = {"ok": False}
    try:
        ctx = hsm_tls.HsmServerContext(a.config, a.cert, a.uri)      # falla cerrado si la clave es exportable, falta o el certificado no corresponde
        summary["clave_cargada_y_no_exportable"] = True
        results, timings = [], []
        for _ in range(a.n):
            one_connection(ctx, a.openssl, a.ca, results, timings)
        ok = [r for r in results if r["servidor"] and r["servidor"].get("ok") and r["verificacion_ok"]]
        summary.update(conexiones=len(results), completadas_y_verificadas=len(ok), firmas=sorted({str(r["firma"]) for r in results}),
                       conn=sorted({tuple(r["servidor"]["conn"]) for r in ok}), errores=[r["servidor"] for r in results if not (r["servidor"] or {}).get("ok")][:3])
        if timings:
            summary["ms_por_apreton"] = {"mediana": round(statistics.median(timings), 1), "max": round(max(timings), 1)}
        ctx.close()
        summary["fork_tras_cerrar"] = subprocess.run([sys.executable, "-c", "pass"], capture_output=True).returncode == 0
        summary["ok"] = len(ok) == len(results) == a.n and summary["fork_tras_cerrar"]
    except BaseException as exc:   # noqa: BLE001
        summary["error"] = f"{type(exc).__name__}: {str(exc)[:300]}"
    print(json.dumps(summary, ensure_ascii=False))
    if cleanup:
        cleanup.cleanup()
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
