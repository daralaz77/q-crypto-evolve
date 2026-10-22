"""Localiza un ejecutable `openssl` >= 3.5 para las pruebas que lo usan como tercero (SLH-DSA por línea de comandos, cliente con grupo híbrido).

Antes las rutas de Homebrew estaban escritas a mano: en Linux esas pruebas se SALTABAN en silencio aunque hubiera un OpenSSL 3.5 en el PATH (menos cobertura de la que parecía).
Ahora se prueba Homebrew y, si no, el del PATH, pero SOLO si su versión es >= 3.5: el `openssl` de macOS es LibreSSL y no sirve (no tiene el híbrido ni SLH-DSA).
"""
import os
import re
import shutil
import subprocess

_HOMEBREW = ("/opt/homebrew/opt/openssl@3/bin/openssl", "/opt/homebrew/bin/openssl", "/usr/local/opt/openssl@3/bin/openssl", "/usr/local/bin/openssl")


def version_at_least_3_5(path: str) -> bool:
    try:
        out = subprocess.run([path, "version"], capture_output=True, text=True, timeout=20).stdout
    except (OSError, subprocess.TimeoutExpired):
        return False
    m = re.match(r"OpenSSL (\d+)\.(\d+)", out)
    return bool(m) and (int(m.group(1)), int(m.group(2))) >= (3, 5)


def find_openssl() -> str | None:
    for path in (*_HOMEBREW, shutil.which("openssl")):
        if path and os.path.exists(path) and version_at_least_3_5(path):
            return path
    return None
