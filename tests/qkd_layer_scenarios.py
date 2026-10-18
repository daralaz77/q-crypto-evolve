"""Escenarios de QIL1 (capa interna con clave QKD) ejecutados en un PROCESO NUEVO, igual que tests/tls_scenarios.py.

`qce.transport.qkd_layer` importa `tls13` primero, y `tls13` falla cerrado si `cryptography` ya estaba cargada: por eso nada de esto
puede correr dentro del proceso de pytest. Uso: python tests/qkd_layer_scenarios.py <escenario>  →  imprime un JSON (última línea).
"""
import json
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path

from qce.transport import qkd_layer as Q  # noqa: E402  (importa tls13 primero)
from qce.transport import pki, tls13  # noqa: E402

KEY = bytes(range(32))
KID = b"qkd-key-0001"


def err(fn):
    try:
        fn()
        return "ok"
    except Exception as exc:  # noqa: BLE001
        return type(exc).__name__


class Lab:
    """Servidor TLS real con la capa QKD en su manejador; guarda lo que ocurrió en el servidor."""

    def __init__(self, d, keys=None, extra_cert=None):
        ca, ck, cc = pki.issue_ca(d)
        self.ca = ca
        self.cert, self.key = pki.issue_leaf(d, ck, cc, "localhost", server=True)
        self.cert_der = ssl_pem_to_der(self.cert)
        self.store = Q.OneTimeKeys({KID: KEY} if keys is None else keys)
        self.out = {}
        self.srv = tls13.TlsServer(tls13.server_context(self.cert, self.key), self.handle).start()

    def handle(self, conn, peer):
        try:
            layer = Q.server_layer(conn, self.store.take, self.cert_der)
            self.out["server"] = "ok"
            self.out["server_th"] = layer.transcript_hash.hex()
        except Exception as exc:  # noqa: BLE001
            self.out["server"] = type(exc).__name__
            return
        try:
            layer.write(layer.read()[::-1])
        except Exception as exc:  # noqa: BLE001  (el cliente puede cerrar sin enviar nada)
            self.out["server_after"] = type(exc).__name__

    def client(self):
        return tls13.connect(tls13.client_context(self.ca), "127.0.0.1", self.srv.port, "localhost", timeout=5)

    def close(self):
        self.srv.close()


def ssl_pem_to_der(path):
    import ssl
    return ssl.PEM_cert_to_DER_cert(Path(path).read_text())


def sc_honest():
    """Apretón real + eco; devuelve los datos crudos para que la prueba re-derive todo desde la especificación."""
    frames = []
    orig = tls13.send_frame

    def recording(sock, data):
        frames.append(bytes(data))
        return orig(sock, data)
    with tempfile.TemporaryDirectory() as td:
        lab = Lab(Path(td))
        tls13.send_frame = Q.tls13.send_frame = recording
        c = lab.client()
        layer = Q.client_layer(c, KID, KEY)
        layer.write(b"hola qkd")
        reply = layer.read()
        time.sleep(0.2)
        out = {"reply": reply.decode(), "version": c.version(), "server": lab.out.get("server"),
               "th_equal": layer.transcript_hash.hex() == lab.out.get("server_th"), "bind": c.get_channel_binding("tls-unique").hex(),
               "cert": lab.cert_der.hex(), "key": KEY.hex(), "key_id": KID.hex(), "frames": [f.hex() for f in frames],
               "th": layer.transcript_hash.hex()}
        c.close()
        lab.close()
    return out


def sc_reuse_and_wrong_key():
    out = {}
    with tempfile.TemporaryDirectory() as td:
        lab = Lab(Path(td))
        for i in range(2):  # el mismo id dos veces
            lab.out.clear()
            c = lab.client()
            out[f"uso_{i + 1}_cliente"] = err(lambda: Q.client_layer(c, KID, KEY))
            c.close()
            time.sleep(0.2)
            out[f"uso_{i + 1}_servidor"] = lab.out.get("server")
        lab.store.add(KID, KEY)  # clave equivocada del lado cliente
        lab.out.clear()
        c = lab.client()
        out["clave_equivocada_cliente"] = err(lambda: Q.client_layer(c, KID, bytes(32)))
        c.close()
        time.sleep(0.2)
        out["clave_equivocada_servidor"] = lab.out.get("server")
        lab.out.clear()  # id desconocido
        c = lab.client()
        out["id_desconocido_cliente"] = err(lambda: Q.client_layer(c, b"no-existe", KEY))
        c.close()
        time.sleep(0.2)
        out["id_desconocido_servidor"] = lab.out.get("server")
        lab.close()
    return out


def sc_rogue_mitm():
    """Certificado FALSO aceptado por el cliente; el atacante retransmite hacia el servidor real. La capa debe cortar a los dos."""
    out = {}
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        lab = Lab(d)
        rd = d / "r"
        rd.mkdir()
        rca, rk, rc = pki.issue_ca(rd)
        rcert, rkey = pki.issue_leaf(rd, rk, rc, "localhost", server=True)
        log = {}

        def mitm(conn, peer):
            up = tls13.connect(tls13.client_context(lab.ca), "127.0.0.1", lab.srv.port, "localhost", timeout=5)
            try:
                tls13.send_frame(up, tls13.recv_frame(conn))   # HELLO
                tls13.send_frame(conn, tls13.recv_frame(up))   # ACCEPT del servidor real
                tls13.send_frame(up, tls13.recv_frame(conn))   # CONFIRM del cliente
                log["relay"] = "completo"
            except Exception as exc:  # noqa: BLE001
                log["relay"] = type(exc).__name__
            up.close()
        m = tls13.TlsServer(tls13.server_context(rcert, rkey), mitm).start()
        c = tls13.connect(tls13.client_context(rca), "127.0.0.1", m.port, "localhost", timeout=5)
        out["cliente"] = err(lambda: Q.client_layer(c, KID, KEY))
        c.close()
        time.sleep(0.4)
        out["servidor_real"] = lab.out.get("server")
        out["retransmision"] = log.get("relay")
        m.close()
        lab.close()
    return out


def sc_binding_checks():
    class Fake:
        def __init__(self, version="TLSv1.3", bind=b"x" * 48, cert=b"c" * 10):
            self._v, self._b, self._c = version, bind, cert
            self.sent = []

        def version(self): return self._v
        def get_channel_binding(self, kind): return self._b
        def getpeercert(self, binary_form=False): return self._c
        def sendall(self, b): self.sent.append(b)
        def recv(self, n): raise OSError("fake")

    out = {"tls12": err(lambda: Q.client_layer(Fake("TLSv1.2"), KID, KEY)),
           "sin_binding": err(lambda: Q.client_layer(Fake(bind=None), KID, KEY)),
           "binding_corto": err(lambda: Q.client_layer(Fake(bind=b"x" * (Q.BIND_MIN - 1)), KID, KEY)),
           "binding_minimo_ok": err(lambda: Q.client_layer(Fake(bind=b"x" * Q.BIND_MIN), KID, KEY)),   # llega a enviar el HELLO y falla al leer
           "sin_certificado": err(lambda: Q.client_layer(Fake(cert=None), KID, KEY)),
           "clave_corta": err(lambda: Q.client_layer(Fake(), KID, KEY[:Q.QKD_KEY_MIN - 1])),
           "clave_larga": err(lambda: Q.client_layer(Fake(), KID, bytes(Q.QKD_KEY_MAX + 1))),
           "clave_minima_ok": err(lambda: Q.client_layer(Fake(), KID, bytes(Q.QKD_KEY_MIN))),
           "clave_maxima_ok": err(lambda: Q.client_layer(Fake(), KID, bytes(Q.QKD_KEY_MAX))),
           "id_vacio": err(lambda: Q.client_layer(Fake(), b"", KEY)),
           "id_largo": err(lambda: Q.client_layer(Fake(), bytes(Q.KEY_ID_MAX + 1), KEY)),
           "id_maximo_ok": err(lambda: Q.client_layer(Fake(), bytes(Q.KEY_ID_MAX), KEY)),
           "id_minimo_ok": err(lambda: Q.client_layer(Fake(), b"k", KEY))}
    f = Fake()
    err(lambda: Q.client_layer(f, KID, KEY, rng=lambda n: b"\x07" * n))
    out["hello_enviado"] = f.sent[0][4:].hex() if f.sent else None
    out["server_sin_binding"] = err(lambda: Q.server_layer(Fake(bind=None), Q.OneTimeKeys().take, b"c"))
    return out


def sc_hello_parsing():
    good = Q.encode_hello(KID, b"n" * 32)
    cases = {"ok": good, "version_mala": b"QIL2" + good[4:], "corto": good[:3], "id_cero": b"QIL1\x00" + b"n" * 32,
             "id_demasiado_largo": b"QIL1" + bytes([Q.KEY_ID_MAX + 1]) + bytes(Q.KEY_ID_MAX + 1) + b"n" * 32,
             "falta_un_byte": good[:-1], "sobra_un_byte": good + b"x", "id_maximo": Q.encode_hello(bytes(Q.KEY_ID_MAX), b"n" * 32)}
    out = {k: err(lambda v=v: Q.decode_hello(v)) for k, v in cases.items()}
    out["roundtrip"] = Q.decode_hello(good) == (KID, b"n" * 32)
    return out


def sc_records():
    """Capa de registros sobre un par de sockets (sin TLS): lo que protege la propia capa. Un registro que falla es FATAL: cada prueba usa un par nuevo."""
    th = b"t" * 32
    k_ab, k_ba = bytes(range(32)), bytes(range(32, 64))

    def pair(th_b=th):
        a, b = socket.socketpair()
        return a, b, Q.Layer(a, k_ab, k_ba, th), Q.Layer(b, k_ba, k_ab, th_b)
    out = {}
    a, b, A, B = pair()
    A.write(b"uno"); out["ida"] = B.read().decode()
    B.write(b"dos"); out["vuelta"] = A.read().decode()
    A.write(b"tres"); out["segundo"] = B.read().decode()
    a, b, A, B = pair()  # manipulación de un bit
    A.write(b"cuatro")
    raw = bytearray(tls13.recv_frame(b)); raw[0] ^= 1
    tls13.send_frame(a, bytes(raw))
    out["manipulado"] = err(B.read)
    a, b, A, B = pair()  # repetición del mismo registro
    A.write(b"cinco")
    r5 = tls13.recv_frame(b)
    tls13.send_frame(a, r5); out["cinco"] = B.read().decode()
    tls13.send_frame(a, r5); out["repeticion"] = err(B.read)
    a, b, A, B = pair()  # reflexión: un registro A→B devuelto a A
    A.write(b"eco")
    tls13.send_frame(b, tls13.recv_frame(b))
    out["reflexion"] = err(A.read)
    a, b, A, B = pair(th_b=b"u" * 32)  # otro transcript
    A.write(b"x"); out["otro_transcript"] = err(B.read)
    a, b, A, B = pair()  # reordenación
    A.write(b"m1"); A.write(b"m2")
    m1, m2 = tls13.recv_frame(b), tls13.recv_frame(b)
    tls13.send_frame(a, m2); tls13.send_frame(a, m1)
    out["reordenado"] = err(B.read)
    a, b, A, B = pair()  # límites
    A._n_out = B._n_in = Q.MAX_RECORDS - 1
    A.write(b"ultimo"); out["ultimo"] = B.read().decode()
    out["contador_agotado_escritura"] = err(lambda: A.write(b"x"))
    out["contador_agotado_lectura"] = err(B.read)
    a, b, A, B = pair()
    out["demasiado_grande"] = err(lambda: A.write(bytes(Q.MAX_PLAINTEXT + 1)))
    t = threading.Thread(target=lambda: out.__setitem__("maximo_ok", err(lambda: A.write(bytes(Q.MAX_PLAINTEXT)))))
    t.start()
    out["maximo_leido"] = len(B.read())
    t.join(5)
    return out


def sc_bad_client_tag():
    """Cliente que conoce la clave para verificar al servidor pero responde con una etiqueta equivocada: el servidor debe rechazar."""
    out = {}
    with tempfile.TemporaryDirectory() as td:
        lab = Lab(Path(td))
        c = lab.client()
        tls13.send_frame(c, Q.encode_hello(KID, b"n" * 32))
        accept = tls13.recv_frame(c)
        out["accept_len"] = len(accept)
        tls13.send_frame(c, bytes(32))
        c.close()
        time.sleep(0.3)
        out["servidor"] = lab.out.get("server")
        lab.store.add(KID, KEY)  # HELLO malformado: el servidor no debe ni consumir la clave
        c = lab.client()
        tls13.send_frame(c, b"QIL1\x00xx")
        c.close()
        time.sleep(0.3)
        out["hello_malformado_servidor"] = lab.out.get("server")
        out["clave_sigue_disponible"] = lab.store.take(KID) == KEY
        for n, label in ((Q.QKD_KEY_MIN - 1, "corta"), (Q.QKD_KEY_MAX + 1, "larga")):   # la fuente entrega material fuera de rango
            lab.store.add(KID, bytes(n))
            lab.out.clear()
            c = lab.client()
            tls13.send_frame(c, Q.encode_hello(KID, b"n" * 32))
            time.sleep(0.3)
            c.close()
            out[f"clave_{label}_servidor"] = lab.out.get("server")
        lab.close()
    return out


def sc_broker():
    """Integración con el KeyBroker: política, reserva y consumo único; dos extremos de un enlace simulado."""
    from qce.core.chainlog import ChainLog
    from qce.core.policy import Policy
    from qce.qkd.broker import KeyBroker
    from qce.qkd.devices import DeviceRegistry, SimulatedAdapter, SimulatedLink

    out = {}
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        clock = time.time
        link = SimulatedLink("L1")
        brokers = []
        for name in ("devA", "devB"):
            audit = ChainLog(d / f"{name}.jsonl", clock)
            reg = DeviceRegistry(audit, clock)
            dev = SimulatedAdapter(name, link, clock=clock)
            reg.enroll(name, "SIMULATION", "sim", dev.firmware, dev.identity.public_bytes, approved_by="darwin")
            dev.initialize({"registry": reg})
            link.ends.append(dev) if dev not in link.ends else None
            b = KeyBroker(Policy(allow_simulated_qkd=True), reg, audit, clock, {"L1": {"qil"}})
            b.attach("L1", dev)
            brokers.append(b)
        ba, bb = brokers
        ids = link.generate(2)
        lab = Lab(d)
        lab.store = type("S", (), {"take": staticmethod(Q.broker_taker(bb, "L1", "qil"))})()
        ba.refill("L1", 1, ids[0])
        kid, key = ba.take("L1", "qil", ids[0])
        c = lab.client()
        layer = Q.client_layer(c, kid if isinstance(kid, bytes) else kid.encode(), key)
        layer.write(b"con broker")
        out["eco"] = layer.read().decode()
        c.close()
        time.sleep(0.2)
        out["servidor"] = lab.out.get("server")
        # el servidor ya consumió la clave: el mismo id no vuelve a salir del broker
        out["reutilizar_id"] = Q.broker_taker(bb, "L1", "qil")(ids[0].encode())
        out["id_desconocido"] = Q.broker_taker(bb, "L1", "qil")(b"no-existe")
        out["id_no_ascii"] = Q.broker_taker(bb, "L1", "qil")(b"\xff\xfe")
        out["consumidor_no_autorizado"] = Q.broker_taker(bb, "L1", "otro")(ids[1].encode())
        quarantined = link.generate(1, qber=0.4)[0]   # QBER de espionaje: el broker pone el enlace en cuarentena
        out["enlace_en_cuarentena"] = Q.broker_taker(bb, "L1", "qil")(quarantined.encode())
        out["cuarentena_registrada"] = bool(bb.status("L1")["blocked"])
        lab.close()
    return out


def sc_nonce_freshness():
    """Dos sesiones con claves distintas: los nonces de cliente y servidor, y por tanto th, no pueden repetirse."""
    frames = []
    orig = tls13.send_frame

    def recording(sock, data):
        frames.append(bytes(data))
        return orig(sock, data)
    with tempfile.TemporaryDirectory() as td:
        lab = Lab(Path(td), keys={b"k1": KEY, b"k2": KEY})
        tls13.send_frame = Q.tls13.send_frame = recording
        ths = []
        for kid in (b"k1", b"k2"):
            c = lab.client()
            ths.append(Q.client_layer(c, kid, KEY).transcript_hash.hex())
            c.close()
            time.sleep(0.2)
        hellos = [f for f in frames if f[:4] == b"QIL1"]
        accepts = [f for f in frames if len(f) == Q.NONCE_LEN + Q.TAG_LEN]
        lab.close()
    return {"hellos": len(hellos), "nc_distintos": hellos[0][-Q.NONCE_LEN:] != hellos[1][-Q.NONCE_LEN:],
            "ns_distintos": accepts[0][:Q.NONCE_LEN] != accepts[1][:Q.NONCE_LEN], "th_distintos": ths[0] != ths[1],
            "nc_no_cero": hellos[0][-Q.NONCE_LEN:] != bytes(Q.NONCE_LEN), "ns_no_cero": accepts[0][:Q.NONCE_LEN] != bytes(Q.NONCE_LEN)}


def sc_bad_accept():
    """Servidor TLS que responde con un ACCEPT de longitud equivocada: el cliente debe rechazarlo (y no tocar la clave)."""
    out = {}
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        ca, ck, cc = pki.issue_ca(d)
        cert, key = pki.issue_leaf(d, ck, cc, "localhost", server=True)
        for n in (Q.NONCE_LEN + Q.TAG_LEN - 1, Q.NONCE_LEN + Q.TAG_LEN + 1, 0):
            def handler(conn, peer, n=n):
                try:
                    tls13.recv_frame(conn)
                    tls13.send_frame(conn, bytes(n))
                    time.sleep(0.3)
                except Exception:  # noqa: BLE001
                    pass
            srv = tls13.TlsServer(tls13.server_context(cert, key), handler).start()
            c = tls13.connect(tls13.client_context(ca), "127.0.0.1", srv.port, "localhost", timeout=5)
            out[f"accept_{n}"] = err(lambda: Q.client_layer(c, KID, KEY))
            c.close()
            srv.close()
    return out


def sc_constants():
    names = ("VERSION TH_LABEL INFO_CONF INFO_C2S INFO_S2C REC_AAD_LABEL ROLE_CLIENT ROLE_SERVER NONCE_LEN TAG_LEN KEY_ID_MAX QKD_KEY_MIN "
             "QKD_KEY_MAX BIND_MIN MAX_RECORDS").split()
    return {n: (getattr(Q, n).decode() if isinstance(getattr(Q, n), bytes) else getattr(Q, n)) for n in names} | {"MAX_PLAINTEXT": Q.MAX_PLAINTEXT, "MAX_FRAME": tls13.MAX_FRAME}


SCEN = {"nonce_freshness": sc_nonce_freshness, "bad_accept": sc_bad_accept, "constants": sc_constants, "honest": sc_honest, "reuse_and_wrong_key": sc_reuse_and_wrong_key, "rogue_mitm": sc_rogue_mitm, "binding_checks": sc_binding_checks,
        "hello_parsing": sc_hello_parsing, "bad_client_tag": sc_bad_client_tag, "records": sc_records, "broker": sc_broker}

if __name__ == "__main__":
    print(json.dumps(SCEN[sys.argv[1]](), ensure_ascii=False))
