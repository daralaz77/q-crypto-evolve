"""EMULADOR de un KME de ETSI GS QKD 014 — SIMULACIÓN DE LABORATORIO, no un dispositivo QKD ni un KME real.

Genera las claves con `os.urandom` (no hay física cuántica) y las entrega por la API REST de la interfaz 014 a una SAE maestra (`enc_keys`) y a una esclava
(`dec_keys`, una sola vez por clave), tras comprobar el certificado de cliente de cada una (CN = identificador de la SAE). Sirve para probar el adaptador
`qce.qkd.etsi014.Etsi014Adapter` de extremo a extremo; no demuestra nada sobre KMEs de fabricantes. El contexto TLS lo aporta quien lo arranca.
"""
from __future__ import annotations

import base64
import json
import os
import re
import ssl
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

KEY_PATH = re.compile(r"^/api/v1/keys/([A-Za-z0-9._:@-]{1,128})/(status|enc_keys|dec_keys)$")


class EmulatedKME:
    def __init__(self, ssl_context: ssl.SSLContext, master_sae: str, slave_sae: str, key_size: int = 256, max_keys: int = 32, max_per_request: int = 4,
                 host: str = "127.0.0.1", port: int = 0) -> None:
        self.master, self.slave, self.key_size, self.max_keys, self.max_per_request = master_sae, slave_sae, key_size, max_keys, max_per_request
        self._store: dict[str, bytes] = {}
        self._lock = threading.Lock()
        self.requests: list[tuple[str, str, str]] = []   # (sae, método, ruta): para que las pruebas vean quién pidió qué
        kme = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):   # sin ruido en las pruebas
                pass

            def _reply(self, status, obj):
                data = json.dumps(obj).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _sae(self):
                cert = self.connection.getpeercert()
                for rdn in (cert or {}).get("subject", ()):
                    for k, v in rdn:
                        if k == "commonName":
                            return v
                return None

            def _handle(self, method):
                sae = self._sae()
                kme.requests.append((str(sae), method, self.path))
                m = KEY_PATH.match(self.path)
                if sae not in (kme.master, kme.slave):
                    return self._reply(401, {"message": "SAE no autorizada"})
                if not m:
                    return self._reply(400, {"message": "ruta desconocida"})
                other, op = m.group(1), m.group(2)
                if other != (kme.slave if sae == kme.master else kme.master):
                    return self._reply(401, {"message": "SAE par no autorizada para esta SAE"})
                length = int(self.headers.get("Content-Length", "0"))
                try:
                    body = json.loads(self.rfile.read(length)) if length else {}
                except ValueError:
                    return self._reply(400, {"message": "cuerpo no es JSON"})
                with kme._lock:
                    if op == "status" and method == "GET":
                        return self._reply(200, {"source_KME_ID": "KME-A", "target_KME_ID": "KME-B", "master_SAE_ID": kme.master, "slave_SAE_ID": kme.slave,
                                                 "key_size": kme.key_size, "stored_key_count": len(kme._store), "max_key_count": kme.max_keys,
                                                 "max_key_per_request": kme.max_per_request, "max_key_size": 1024, "min_key_size": 64, "max_SAE_ID_count": 0})
                    if op == "enc_keys" and method == "POST" and sae == kme.master:
                        n, size = body.get("number", 1), body.get("size", kme.key_size)
                        if not (isinstance(n, int) and isinstance(size, int)) or n < 1 or n > kme.max_per_request or size % 8 or not 64 <= size <= 1024:
                            return self._reply(400, {"message": "número o tamaño de clave no admitido"})
                        if len(kme._store) + n > kme.max_keys:
                            return self._reply(503, {"message": "KME sin capacidad para más claves"})
                        out = []
                        for _ in range(n):
                            kid, key = str(uuid.uuid4()), os.urandom(size // 8)
                            kme._store[kid] = key
                            out.append({"key_ID": kid, "key": base64.b64encode(key).decode()})
                        return self._reply(200, {"keys": out})
                    if op == "dec_keys" and method == "POST" and sae == kme.slave:
                        ids = [x.get("key_ID") for x in body.get("key_IDs", []) if isinstance(x, dict)]
                        if not ids or len(ids) > kme.max_per_request:
                            return self._reply(400, {"message": "key_IDs ausentes o demasiados"})
                        if any(i not in kme._store for i in ids):
                            return self._reply(400, {"message": "key_ID desconocido o ya entregado"})
                        out = [{"key_ID": i, "key": base64.b64encode(kme._store.pop(i)).decode()} for i in ids]   # entrega única
                        return self._reply(200, {"keys": out})
                return self._reply(400, {"message": "operación no permitida para esta SAE"})

            def do_GET(self):
                self._handle("GET")

            def do_POST(self):
                self._handle("POST")

        class Quiet(ThreadingHTTPServer):
            def handle_error(self, request, client_address):   # un cliente que corta o falla el TLS no debe llenar la salida de las pruebas
                pass
        self._srv = Quiet((host, port), H)
        self._srv.socket = ssl_context.wrap_socket(self._srv.socket, server_side=True)
        self.port = self._srv.server_address[1]
        self._thread = threading.Thread(target=self._srv.serve_forever, daemon=True)

    @property
    def stored(self) -> int:
        return len(self._store)

    def start(self) -> "EmulatedKME":
        self._thread.start()
        return self

    def close(self) -> None:
        self._srv.shutdown()
        self._srv.server_close()
