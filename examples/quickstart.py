"""Demostración de punta a punta en un solo comando (SIMULACIÓN: el KME es un emulador, no hay equipo QKD).

    .venv/bin/python examples/quickstart.py

Qué hace, en orden, y lo que imprime es lo que realmente ocurrió:
  1. levanta un KME ETSI GS QKD 014 emulado con TLS mutuo y una PKI de laboratorio;
  2. la SAE maestra pide una clave por HTTPS y la SAE esclava la recoge por su key_ID (el KME la entrega una sola vez);
  3. con esa clave como PSK externa se abre una conexión TLS 1.3 estándar con el grupo híbrido X25519MLKEM768;
  4. comprueba que la clave ya no se puede volver a recoger.
El paso 3 necesita OpenSSL ≥ 3.5; si no está, lo dice y se detiene tras el paso 2 (no finge).
"""
from __future__ import annotations

import hashlib
import ssl
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from qce.core.chainlog import ChainLog  # noqa: E402
from qce.core.policy import Policy  # noqa: E402
from qce.qkd.broker import KeyBroker  # noqa: E402
from qce.qkd.devices import DeviceRegistry  # noqa: E402
from qce.qkd.etsi014 import Etsi014Adapter, HttpsTransport  # noqa: E402
from qce.qkd.etsi014_emulator import EmulatedKME  # noqa: E402
from qce.qkd.sources import BrokerSource  # noqa: E402
from qce.transport import pki  # noqa: E402
from qce.transport import tls13_psk as P  # noqa: E402

MASTER, SLAVE = "sae-master", "sae-slave"


def say(n: int, text: str) -> None:
    print(f"[{n}] {text}", flush=True)


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="qce-quickstart-") as d:
        tmp = Path(d)
        ca, ck, cc = pki.issue_ca(tmp, days=1)
        scert, skey = pki.issue_leaf(tmp, ck, cc, "kme.lab", server=True)
        sae = {n: pki.issue_leaf(tmp, ck, cc, n, server=False) for n in (MASTER, SLAVE)}

        srv_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        srv_ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        srv_ctx.load_cert_chain(str(scert), str(skey))
        srv_ctx.verify_mode = ssl.CERT_REQUIRED
        srv_ctx.load_verify_locations(str(ca))
        kme = EmulatedKME(srv_ctx, MASTER, SLAVE).start()
        say(1, f"KME ETSI GS QKD 014 EMULADO escuchando en 127.0.0.1:{kme.port} (TLS 1.3 con autenticación mutua; simulación, no es QKD real)")

        fp = hashlib.sha256(ssl.PEM_cert_to_DER_cert(scert.read_text(encoding="utf-8"))).digest()

        def client_ctx(cert, key):
            c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            c.minimum_version = ssl.TLSVersion.TLSv1_3
            c.load_verify_locations(str(ca))
            c.load_cert_chain(str(cert), str(key))
            return c

        brokers = {}
        for role, me, peer in (("master", MASTER, SLAVE), ("slave", SLAVE, MASTER)):
            audit = ChainLog(tmp / f"audit-{role}.jsonl")
            reg = DeviceRegistry(audit)
            ad = Etsi014Adapter(f"kme-{role}", HttpsTransport("127.0.0.1", kme.port, client_ctx(*sae[me])), me, peer, role, is_simulation=True)
            reg.enroll(ad.device_id, "ETSI-014", "KME", "n/a", fp, approved_by="quickstart", protocol="ETSI-014-KME", spec=(("trusted_hops", 0),))
            ad.initialize({"registry": reg})
            broker = KeyBroker(Policy(allow_simulated_qkd=True), reg, audit, allowed_consumers={"L1": {"sess"}})
            broker.attach("L1", ad)
            brokers[role] = broker

        brokers["master"].refill("L1", 1)
        kid, key = brokers["master"].take("L1", "sess")
        kid = kid if isinstance(kid, bytes) else kid.encode()
        say(2, f"la SAE maestra pidió una clave: key_ID={kid.decode()}, {len(key) * 8} bits (la clave no se imprime)")

        try:
            P._load()
        except P.PskTransportUnavailable as e:
            say(3, f"no hay OpenSSL ≥ 3.5, el puente TLS no puede correr aquí: {e}")
            kme.close()
            return 0

        server = P.PskServer(BrokerSource(brokers["slave"], "L1", "sess"), lambda c: c.send_frame(c.recv_frame()[::-1])).start()
        conn = P.connect_tcp("127.0.0.1", server.port, kid, key, timeout=10)
        conn.send_frame(b"hola QKD")
        echo = conn.recv_frame()
        say(3, f"TLS 1.3 con la clave del KME como PSK externa: versión={conn.version}, grupo={conn.group}, cifrado={conn.cipher}, PSK usada={conn.psk_used}")
        say(3, f"la SAE esclava recogió la MISMA clave por su key_ID y devolvió el mensaje invertido: {echo!r} (si las claves difirieran, el apretón TLS habría fallado)")
        conn.close()
        server.close()

        try:
            brokers["slave"].take("L1", "sess", kid)
            say(4, "ERROR: la clave se pudo recoger por segunda vez")
            kme.close()
            return 1
        except Exception as e:  # noqa: BLE001  (cualquier rechazo es el resultado esperado)
            say(4, f"segunda recogida de la misma clave: rechazada ({type(e).__name__}); el KME entrega cada key_ID una sola vez")

        kme.close()
        print("\nListo. Todo lo anterior es simulación de laboratorio, sin revisión humana externa: ver LIMITATIONS.md.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
