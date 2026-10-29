"""Panel local de SOLO LECTURA de Q-Crypto Evolve. `python panel/server.py` y abre http://127.0.0.1:8765

Reglas: escucha solo en 127.0.0.1; únicamente GET/HEAD; sin endpoints que escriban o ejecuten; valida la cabecera Host
(contra DNS rebinding); CSP estricta (sin scripts ni estilos en línea); no lee claves privadas.
"""
from __future__ import annotations

import argparse
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import data  # noqa: E402

STATIC = Path(__file__).resolve().parent / "static"
TYPES = {".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8"}
ASSETS = {"/": "index.html", "/index.html": "index.html", "/panel.css": "panel.css", "/app.js": "app.js", "/boot.js": "boot.js"}
CSP = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"


def make_handler(root: Path):
    class Handler(BaseHTTPRequestHandler):
        server_version = "QCEPanel"

        def _send(self, code: int, body: bytes, ctype: str, head_only: bool = False) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Security-Policy", CSP)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            if not head_only:
                self.wfile.write(body)

        def _host_ok(self) -> bool:
            host = (self.headers.get("Host") or "").rsplit(":", 1)[0]
            return host in ("127.0.0.1", "localhost", "[::1]")

        def _serve(self, head_only: bool) -> None:
            if not self._host_ok():
                return self._send(403, b"host no permitido", "text/plain; charset=utf-8", head_only)
            path = self.path.split("?", 1)[0]
            if path == "/api/estado":
                body = json.dumps(data.snapshot(root), ensure_ascii=False).encode()
                return self._send(200, body, "application/json; charset=utf-8", head_only)
            name = ASSETS.get(path)  # lista cerrada: la ruta pedida NUNCA se usa para construir un camino de archivo
            if name is None:
                return self._send(404, b"no encontrado", "text/plain; charset=utf-8", head_only)
            f = STATIC / name
            if not f.is_file():
                return self._send(404, b"no encontrado", "text/plain; charset=utf-8", head_only)
            self._send(200, f.read_bytes(), TYPES[f.suffix], head_only)

        def do_GET(self) -> None:  # noqa: N802
            self._serve(False)

        def do_HEAD(self) -> None:  # noqa: N802
            self._serve(True)

        def _no(self) -> None:
            self._send(405, b"solo lectura", "text/plain; charset=utf-8")

        do_POST = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = _no  # noqa: N815

        def log_message(self, *a) -> None:  # sin registros con rutas
            pass

    return Handler


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    a = ap.parse_args()
    srv = ThreadingHTTPServer(("127.0.0.1", a.port), make_handler(a.root.resolve()))
    print(f"Panel de solo lectura en http://127.0.0.1:{srv.server_port}  (Ctrl+C para salir)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
