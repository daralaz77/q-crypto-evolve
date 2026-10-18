"""EXPERIMENTO (no es código del producto ni está cubierto por las puertas): capa interna con clave QKD sobre TLS 1.3 híbrido, ligada a la sesión TLS.
Ejecutar desde la raíz del proyecto: PYTHONPATH=. python docs/experimentos/qkd_inner_layer_poc.py"""
from qce.transport import tls13, pki          # tls13 PRIMERO (antes de hmac/hashlib/cryptography)
import hashlib, hmac, os, ssl, tempfile, threading, time
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

QKD = {b"qkd-id-1": os.urandom(32)}

def derive(qkd_key, bind):
    okm = HKDF(algorithm=hashes.SHA256(), length=96, salt=bind, info=b"QCE-QKD-INNER/1").derive(qkd_key)
    return okm[:32], okm[32:64], okm[64:96]

def mac(k, m): return hmac.new(k, m, hashlib.sha256).digest()

class Inner:
    def __init__(self, sock, send_key, recv_key):
        self.s, self.send, self.recv, self.n_out, self.n_in = sock, ChaCha20Poly1305(send_key), ChaCha20Poly1305(recv_key), 0, 0
    def write(self, data):
        tls13.send_frame(self.s, self.send.encrypt(self.n_out.to_bytes(12, "big"), data, b"")); self.n_out += 1
    def read(self):
        ct = tls13.recv_frame(self.s); pt = self.recv.decrypt(self.n_in.to_bytes(12, "big"), ct, b""); self.n_in += 1; return pt

def client_inner(sock, key_id, qkd_key):
    bind = sock.get_channel_binding("tls-unique")
    tls13.send_frame(sock, key_id)                       # el id viaja DENTRO de TLS
    c2s, s2c, conf = derive(qkd_key, bind)
    tag = mac(conf, b"client" + bind); tls13.send_frame(sock, tag)
    if not hmac.compare_digest(tls13.recv_frame(sock), mac(conf, b"server" + bind + tag)):
        raise ValueError("el servidor no demostró conocer la clave QKD ligada a esta sesión")
    return Inner(sock, c2s, s2c)

def server_inner(sock, store):
    bind = sock.get_channel_binding("tls-unique")
    key_id = tls13.recv_frame(sock)
    qkd_key = store.pop(key_id, None)                    # consumo único
    if qkd_key is None: raise ValueError("clave QKD desconocida o ya consumida")
    c2s, s2c, conf = derive(qkd_key, bind)
    tag = tls13.recv_frame(sock)
    if not hmac.compare_digest(tag, mac(conf, b"client" + bind)): raise ValueError("el cliente no demostró conocer la clave QKD ligada a esta sesión")
    tls13.send_frame(sock, mac(conf, b"server" + bind + tag))
    return Inner(sock, s2c, c2s)

def run():
    out = {}
    with tempfile.TemporaryDirectory() as td:
        d = Path(td); ca, ck, cc = pki.issue_ca(d); cert, key = pki.issue_leaf(d, ck, cc, "localhost", server=True)
        result = {}
        def handler(conn, peer):
            try:
                inner = server_inner(conn, store); inner.write(inner.read()[::-1]); result["server"] = "ok"
            except Exception as e: result["server"] = f"rechaza: {e}"
        # 1) caso honesto
        store = dict(QKD); srv = tls13.TlsServer(tls13.server_context(cert, key), handler).start()
        t0 = time.perf_counter(); c = tls13.connect(tls13.client_context(ca), "127.0.0.1", srv.port, "localhost"); t1 = time.perf_counter()
        inner = client_inner(c, b"qkd-id-1", QKD[b"qkd-id-1"]); t2 = time.perf_counter()
        inner.write(b"hola qkd"); out["honesto"] = inner.read().decode(); out["ms_tls"] = round((t1 - t0) * 1000, 2); out["ms_capa_qkd"] = round((t2 - t1) * 1000, 2)
        # el binding coincide en ambos extremos?
        out["binding_cliente_hex"] = c.get_channel_binding("tls-unique").hex()[:16]; c.close(); time.sleep(0.2); srv.close()
        # 2) clave QKD equivocada
        store = dict(QKD); result.clear(); srv = tls13.TlsServer(tls13.server_context(cert, key), handler).start()
        c = tls13.connect(tls13.client_context(ca), "127.0.0.1", srv.port, "localhost")
        try: client_inner(c, b"qkd-id-1", os.urandom(32)); out["clave_equivocada"] = "ACEPTADA"
        except Exception as e: out["clave_equivocada"] = f"cliente: {type(e).__name__}"
        c.close(); time.sleep(0.2); out["clave_equivocada_servidor"] = result.get("server"); srv.close()
        # 3) clave QKD ya consumida (repetición del mismo id)
        store = dict(QKD); result.clear(); srv = tls13.TlsServer(tls13.server_context(cert, key), handler).start()
        for i in range(2):
            c = tls13.connect(tls13.client_context(ca), "127.0.0.1", srv.port, "localhost")
            try: client_inner(c, b"qkd-id-1", QKD[b"qkd-id-1"]); r = "aceptada"
            except Exception as e: r = f"rechazada ({type(e).__name__})"
            out[f"uso_{i+1}_del_mismo_id"] = r; c.close(); time.sleep(0.2)
        srv.close()
        # 4) MITM con certificado FALSO aceptado por el cliente: el atacante retransmite hacia el servidor real
        store = dict(QKD); result.clear()
        real = tls13.TlsServer(tls13.server_context(cert, key), handler).start()
        rogue_ca, rk, rc = pki.issue_ca(d / "r") if (d / "r").mkdir() is None else None
        rcert, rkey = pki.issue_leaf(d / "r", rk, rc, "localhost", server=True)
        mitm_log = {}
        def mitm(conn_client, peer):
            up = tls13.connect(tls13.client_context(ca), "127.0.0.1", real.port, "localhost")   # el atacante habla con el servidor real
            try:
                tls13.send_frame(up, tls13.recv_frame(conn_client))     # id
                tls13.send_frame(up, tls13.recv_frame(conn_client))     # tag del cliente (ligado a SU sesión TLS)
                tls13.send_frame(conn_client, tls13.recv_frame(up))     # respuesta del servidor
                mitm_log["relay"] = "completo"
            except Exception as e: mitm_log["relay"] = f"cortado: {type(e).__name__}"
            up.close()
        m = tls13.TlsServer(tls13.server_context(rcert, rkey), mitm).start()
        c = tls13.connect(tls13.client_context(rogue_ca), "127.0.0.1", m.port, "localhost")   # cliente "engañado": confía en la CA falsa
        try: client_inner(c, b"qkd-id-1", QKD[b"qkd-id-1"]); out["mitm_con_certificado_falso"] = "ATACANTE EN MEDIO ACEPTADO"
        except Exception as e: out["mitm_con_certificado_falso"] = f"rechazado por el cliente ({type(e).__name__})"
        c.close(); time.sleep(0.4); out["servidor_real_ante_mitm"] = result.get("server"); m.close(); real.close()
    return out

if __name__ == "__main__":
    import json; print(json.dumps(run(), indent=1, ensure_ascii=False))
