"""Emulador de KME ETSI GS QKD 014 para pruebas, como programa independiente (SIMULACIÓN: no es un equipo QKD).

    qce-kme                      # o:  python qce_kme.py
    qce-kme --port 8443 --master sae-a --slave sae-b --dir ./kme-lab

Crea una PKI de laboratorio (CA, certificado del KME y un certificado por SAE), levanta el emulador con TLS 1.3 y autenticación mutua y
imprime cómo conectarse. Sirve para probar clientes ETSI 014 (por ejemplo `qkdsec doctor`) sin un KME real. Qué NO es: no mide ni protege nada
físico, genera las claves con `os.urandom`, y los certificados caducan en `--days` días. Contraste con una herramienta independiente: docs/ETSI014_ADAPTER.md.
Este archivo vive fuera de `qce/` a propósito: no forma parte del código revisado ni cambia su release_id.
"""
from __future__ import annotations

import argparse
import ssl
import sys
import tempfile
import time
from pathlib import Path

from qce.qkd.etsi014_emulator import EmulatedKME
from qce.transport import pki


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="qce-kme", description="Emulador de KME ETSI GS QKD 014 (simulación, solo para pruebas).")
    ap.add_argument("--host", default="127.0.0.1", help="dirección donde escucha (por defecto solo local)")
    ap.add_argument("--port", type=int, default=0, help="puerto (0 = uno libre)")
    ap.add_argument("--master", default="sae-master", help="CN de la SAE maestra (la única que pide claves)")
    ap.add_argument("--slave", default="sae-slave", help="CN de la SAE esclava (la única que las recoge)")
    ap.add_argument("--key-size", type=int, default=256, help="tamaño de clave en bits (múltiplo de 8)")
    ap.add_argument("--max-keys", type=int, default=32, help="claves almacenadas como máximo")
    ap.add_argument("--dir", default=None, help="dónde dejar la PKI (por defecto, una carpeta temporal)")
    ap.add_argument("--days", type=int, default=1, help="validez de los certificados")
    ap.add_argument("--seconds", type=float, default=0, help="salir tras N segundos (0 = hasta Ctrl-C)")
    a = ap.parse_args(argv)
    if a.key_size % 8 or a.key_size <= 0:
        ap.error("--key-size debe ser un múltiplo de 8")
    if a.master == a.slave:
        ap.error("la SAE maestra y la esclava deben ser distintas")

    out = Path(a.dir) if a.dir else Path(tempfile.mkdtemp(prefix="qce-kme-"))
    out.mkdir(parents=True, exist_ok=True)
    ca, ck, cc = pki.issue_ca(out, days=a.days)
    scert, skey = pki.issue_leaf(out, ck, cc, "kme.lab", server=True, days=a.days)
    mcert, mkey = pki.issue_leaf(out, ck, cc, a.master, server=False, days=a.days)
    lcert, lkey = pki.issue_leaf(out, ck, cc, a.slave, server=False, days=a.days)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(str(scert), str(skey))
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(str(ca))
    kme = EmulatedKME(ctx, a.master, a.slave, key_size=a.key_size, max_keys=a.max_keys, host=a.host, port=a.port).start()

    base = f"https://{a.host}:{kme.port}/api/v1/keys/{a.slave}"
    print(f"KME ETSI GS QKD 014 EMULADO (simulación, no es QKD real) en {a.host}:{kme.port}, TLS 1.3 con autenticación mutua")
    print(f"PKI de laboratorio en {out} (válida {a.days} día(s); las claves privadas están ahí, solo para pruebas)")
    print(f"  CA:             {ca}")
    print(f"  SAE maestra:    {mcert}  {mkey}   (pide claves: enc_keys)")
    print(f"  SAE esclava:    {lcert}  {lkey}   (las recoge: dec_keys)")
    print("Ejemplo con curl (el nombre de host del certificado es kme.lab; con --resolve se valida de verdad):")
    print(f"  curl --cacert {ca} --cert {mcert} --key {mkey} --resolve kme.lab:{kme.port}:{a.host} https://kme.lab:{kme.port}/api/v1/keys/{a.slave}/status")
    print(f"  (URL base de la interfaz: {base})")
    print("Ctrl-C para salir.", flush=True)
    try:
        t0 = time.time()
        while not a.seconds or time.time() - t0 < a.seconds:
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        kme.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
