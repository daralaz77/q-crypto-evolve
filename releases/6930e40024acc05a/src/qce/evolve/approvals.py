"""Revisión independiente (GATE 5) y autorización humana (GATE 6) como declaraciones FIRMADAS.

Una declaración vincula (rol, firmante, release_id, veredicto). Se firma con una clave híbrida
ML-DSA-65 + Ed25519 cuya parte pública está registrada en trust/registry.json.
- Cualquier cambio de código cambia el release_id → invalida revisiones y aprobaciones previas.
- Un agente que no posee la clave privada del revisor/aprobador no puede fabricar la declaración.
LÍMITE DECLARADO: el registro de confianza vive en el repositorio; en producción debe anclarse
fuera (HSM/KMS, firma del propio registro por una raíz offline). Ver LIMITATIONS.md.
"""
from __future__ import annotations

import json
from pathlib import Path

from ..core.errors import AuthenticationFailure, QCEError
from ..pqc.hybrid import HybridSigPrivateKey, hybrid_verify

CTX = b"QCE2/statement"
ROLES = ("implementer", "reviewer", "approver")


def _msg(role: str, signer: str, release_id: str, verdict: str) -> bytes:
    return json.dumps([role, signer, release_id, verdict]).encode()


def register(root: Path, role: str, signer: str, public_bytes: bytes) -> None:
    if role not in ROLES:
        raise QCEError("rol inválido")
    reg = root / "trust" / "registry.json"
    reg.parent.mkdir(exist_ok=True)
    data = json.loads(reg.read_text()) if reg.exists() else {}
    data[signer] = {"role": role, "public_key": public_bytes.hex()}
    reg.write_text(json.dumps(data, indent=2, sort_keys=True))


def sign_statement(root: Path, key: HybridSigPrivateKey, role: str, signer: str, release_id: str,
                   verdict: str, notes: str = "") -> Path:
    if verdict not in ("accept", "reject"):
        raise QCEError("veredicto inválido")
    sig = key.sign(_msg(role, signer, release_id, verdict), CTX)
    d = root / "reviews"
    d.mkdir(exist_ok=True)
    p = d / f"{release_id}.{role}.{signer}.json"
    p.write_text(json.dumps({"role": role, "signer": signer, "release_id": release_id,
                             "verdict": verdict, "notes": notes, "signature": sig.hex()}, indent=2))
    return p


def valid_statements(root: Path, release_id: str, role: str) -> list[str]:
    """Firmantes con declaración 'accept' válida para ESTE release_id y con el rol registrado."""
    reg_p = root / "trust" / "registry.json"
    if not reg_p.exists():
        return []
    reg = json.loads(reg_p.read_text())
    out = []
    for f in sorted((root / "reviews").glob(f"{release_id}.{role}.*.json")) if (root / "reviews").exists() else []:
        s = json.loads(f.read_text())
        entry = reg.get(s["signer"])
        if not entry or entry["role"] != role or s["release_id"] != release_id or s["verdict"] != "accept":
            continue
        try:
            hybrid_verify(bytes.fromhex(entry["public_key"]), _msg(role, s["signer"], release_id, "accept"),
                          bytes.fromhex(s["signature"]), CTX)
        except AuthenticationFailure:
            continue
        out.append(s["signer"])
    return out
