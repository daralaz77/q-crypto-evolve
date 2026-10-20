"""Ceremonia de firma HUMANA para las puertas G5 (revisión independiente) y G6 (autorización): crear la identidad, registrarla y firmar.

Reglas de diseño:
- La clave privada la crea y la guarda LA PERSONA, en un archivo 0600 FUERA del repositorio; este código se niega a escribirla dentro del árbol del proyecto.
  Un agente que no posee esa clave no puede fabricar la declaración (ver approvals.py); y la CLI exige una terminal interactiva para firmar.
- Registrar una identidad en `trust/registry.json` NO la aprueba: solo asocia clave pública, rol y nombre. Quién revisa o autoriza lo decide la persona al firmar.
- Una firma está ligada a un `release_id` (hash del contenido): cualquier cambio posterior de código la invalida. Hay que firmar sobre el commit final.
Límite declarado (LIMITATIONS.md): el registro de confianza vive en el repositorio; en producción debe anclarse fuera.
"""
from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path

from ..core.errors import AuthenticationFailure, QCEError
from ..pqc.hybrid import SIG_PK_LEN, HybridSigPrivateKey
from . import approvals

SEED_HEX_LEN = 2 * (32 + 32)


def fingerprint(public_bytes: bytes) -> str:
    return hashlib.sha256(public_bytes).hexdigest()[:16]


def _inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def new_identity(root: Path, out_dir: Path, name: str) -> tuple[Path, bytes]:
    """Crea `out_dir/<name>.key` (semilla hexadecimal, 0600) y devuelve (ruta, clave pública). No sobrescribe ni escribe dentro del proyecto."""
    if not name or "/" in name or "\\" in name or name.startswith(".") or len(name) > 64:
        raise QCEError("nombre de identidad inválido")
    out_dir = Path(out_dir).expanduser()
    if _inside(out_dir, root):
        raise QCEError("la clave privada no puede guardarse dentro del repositorio del proyecto")
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{name}.key"
    key = HybridSigPrivateKey.generate()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)   # EXCL: jamás pisa una clave existente
    with os.fdopen(fd, "w") as f:
        f.write(key.seed().hex() + "\n")
    return path, key.public_bytes


def load_key(path: Path) -> HybridSigPrivateKey:
    path = Path(path).expanduser()
    mode = path.stat().st_mode & 0o777
    if mode & 0o077:
        raise QCEError(f"la clave privada es accesible a otros usuarios (permisos {oct(mode)}); use chmod 600")
    text = path.read_text().strip()
    if len(text) != SEED_HEX_LEN:
        raise QCEError("archivo de clave con formato inválido")
    try:
        return HybridSigPrivateKey.from_seed(bytes.fromhex(text))
    except ValueError:
        raise QCEError("archivo de clave con formato inválido") from None


def parse_public(text: str) -> bytes:
    text = text.strip()
    if not re.fullmatch(r"[0-9a-fA-F]+", text):   # lo hexadecimal nunca es una ruta (y una cadena de 4 KB como ruta falla en Linux con «nombre demasiado largo»)
        try:
            if Path(text).expanduser().is_file():
                text = Path(text).expanduser().read_text().strip()
        except OSError:
            raise QCEError("la clave pública no es hexadecimal ni un archivo legible") from None
    try:
        pub = bytes.fromhex(text)
    except ValueError:
        raise QCEError("clave pública no hexadecimal") from None
    if len(pub) != SIG_PK_LEN:
        raise QCEError("clave pública con longitud inválida")
    return pub


def register(root: Path, role: str, identity: str, public_bytes: bytes) -> str:
    if role not in ("reviewer", "approver"):
        raise QCEError("las personas se registran como 'reviewer' (G5) o 'approver' (G6)")
    approvals.register(root, role, identity, public_bytes)
    return fingerprint(public_bytes)


def sign(root: Path, key_path: Path, role: str, signer: str, release_id: str, verdict: str, notes: str = "") -> Path:
    """Firma una declaración. Comprueba antes que la clave corresponde a la identidad registrada con ese rol, y después que la firma verifica."""
    import json
    reg_file = root / "trust" / "registry.json"
    reg = json.loads(reg_file.read_text()) if reg_file.exists() else {}
    entry = reg.get(signer)
    if entry is None:
        raise QCEError(f"la identidad {signer!r} no está registrada (use `identity register`)")
    if entry["role"] != role:
        raise QCEError(f"{signer!r} está registrada como {entry['role']!r}, no como {role!r}")
    key = load_key(key_path)
    if key.public_bytes.hex() != entry["public_key"]:
        raise QCEError("la clave privada no corresponde a la clave pública registrada para esa identidad")
    path = approvals.sign_statement(root, key, role, signer, release_id, verdict, notes)
    if verdict == "accept" and signer not in approvals.valid_statements(root, release_id, role):
        path.unlink()
        raise AuthenticationFailure("la declaración recién firmada no verifica; no se conserva")
    return path


def current_release_id(root: Path) -> str:
    from ..recovery import release as rel
    return rel.build_manifest(root, "firma", {}, [], {})["release_id"]
