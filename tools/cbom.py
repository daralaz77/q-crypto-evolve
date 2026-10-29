"""Genera la CBOM (Cryptography Bill of Materials, CycloneDX 1.6) de Q-Crypto Evolve a partir de la política REAL (`qce.core.policy.SUITES`)
más los elementos de transporte/almacenamiento documentados. Sin marca de tiempo: la salida es determinista (se puede comprobar en CI).

  python tools/cbom.py > benchmarks/cbom.cdx.json
  python tools/cbom.py --check            # sale con 1 si benchmarks/cbom.cdx.json no coincide con lo que se generaría hoy

NO está validada contra el esquema oficial de CycloneDX (no hay validador instalado); `tools/tests` comprueba la estructura que usamos.
Los niveles de seguridad cuántica son los de NIST para cada parámetro (ML-KEM-768 = 3, ML-KEM-1024 = 5, ML-DSA-65 = 3, ML-DSA-87 = 5); lo clásico es 0.
"""
import hashlib
import json
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from qce.core.policy import SUITES, Policy  # noqa: E402

OUT = ROOT / "benchmarks" / "cbom.cdx.json"
# (nombre, primitiva CycloneDX, conjunto de parámetros, nivel cuántico NIST, vulnerable a un ordenador cuántico, dónde está en el código)
ATOMS = {
    "X25519": ("kem", "curve25519", 0, True, "qce/pqc/hybrid.py"),
    "Ed25519": ("signature", "curve25519", 0, True, "qce/pqc/hybrid.py"),
    "ML-KEM-768": ("kem", "768", 3, False, "qce/pqc/hybrid.py"),
    "ML-KEM-1024": ("kem", "1024", 5, False, "qce/pqc/hybrid.py"),
    "ML-DSA-65": ("signature", "65", 3, False, "qce/pqc/hybrid.py"),
    "ML-DSA-87": ("signature", "87", 5, False, "qce/pqc/hybrid.py"),
    "SLH-DSA-SHA2-128s": ("signature", "SHA2-128s", 1, False, "qce/pqc/slhdsa.py (puente ctypes, fuera del apretón)"),
    "CHACHA20-POLY1305": ("ae", "256", 5, False, "qce/symmetric/aead.py"),
    "AES-256-GCM": ("ae", "256", 5, False, "qce/symmetric/aead.py"),
    "HKDF-SHA256": ("kdf", "SHA-256", 5, False, "qce/symmetric/aead.py"),
    "HMAC-SHA256": ("mac", "SHA-256", 5, False, "qce/symmetric/aead.py"),
    "scrypt": ("kdf", "scrypt", 5, False, "qce/key_management/keystore.py (almacén cifrado)"),
    "ECDSA-P256": ("signature", "secp256r1", 0, True, "qce/transport/pki.py (PKI de laboratorio del transporte TLS: la autenticación NO es poscuántica)"),
}


def _ref(name: str) -> str:
    return "crypto/algorithm/" + name.lower().replace(" ", "-")


def _algorithm(name: str) -> dict:
    prim, params, qlevel, vulnerable, where = ATOMS[name]
    return {"type": "cryptographic-asset", "bom-ref": _ref(name), "name": name,
            "cryptoProperties": {"assetType": "algorithm",
                                 "algorithmProperties": {"primitive": prim, "parameterSetIdentifier": params, "nistQuantumSecurityLevel": qlevel}},
            "properties": [{"name": "qce:quantum-vulnerable", "value": str(vulnerable).lower()}, {"name": "qce:where", "value": where}]}


def _atoms_of(suite) -> list[str]:
    kem = suite.kem.split("+")
    sig = suite.sig.split("+")
    return [*kem, *sig, suite.aead]


def build() -> dict:
    default = set(Policy().allowed_suites)
    used: set[str] = {"HKDF-SHA256", "HMAC-SHA256", "scrypt", "SLH-DSA-SHA2-128s", "ECDSA-P256"}
    suites = []
    for sid, s in SUITES.items():
        used.update(_atoms_of(s))
        suites.append({"type": "cryptographic-asset", "bom-ref": f"crypto/protocol/{sid.lower()}", "name": sid,
                       "cryptoProperties": {"assetType": "protocol", "protocolProperties": {"type": "other", "version": "QCE1",
                                                                                           "cipherSuites": [{"name": sid, "algorithms": [_ref(a) for a in _atoms_of(s)]}]}},
                       "properties": [{"name": "qce:policy-status", "value": s.status},
                                      {"name": "qce:in-default-policy", "value": str(sid in default).lower()},
                                      {"name": "qce:level", "value": s.level},
                                      {"name": "qce:reviewed-by-human", "value": "false"}]})
    tls = {"type": "cryptographic-asset", "bom-ref": "crypto/protocol/tls-1.3-psk", "name": "TLS 1.3 con PSK externa de QKD",
           "cryptoProperties": {"assetType": "protocol", "protocolProperties": {"type": "tls", "version": "1.3",
                                                                               "cipherSuites": [{"name": "TLS_AES_256_GCM_SHA384", "algorithms": [_ref("AES-256-GCM")]}]}},
           "properties": [{"name": "qce:key-exchange-groups", "value": "X25519MLKEM768, SecP384r1MLKEM1024"},
                          {"name": "qce:authentication", "value": "certificados ECDSA P-256 de la PKI de laboratorio (no poscuánticos)"},
                          {"name": "qce:reviewed-by-human", "value": "false"}]}
    algos = [_algorithm(n) for n in sorted(used)]
    vulnerable = sorted(n for n in used if ATOMS[n][3])
    body = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "metadata": {"component": {"type": "library", "name": "q-crypto-evolve", "bom-ref": "q-crypto-evolve"},
                         "properties": [{"name": "qce:laboratory", "value": "true"},
                                        {"name": "qce:quantum-vulnerable-algorithms-present", "value": ", ".join(vulnerable)},
                                        {"name": "qce:note", "value": "Los híbridos combinan un componente clásico y uno poscuántico: el clásico figura como vulnerable aunque la suite resista."}]},
            "components": algos + suites + [tls]}
    body["serialNumber"] = "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()))
    return body


def render() -> str:
    return json.dumps(build(), indent=1, ensure_ascii=False, sort_keys=True) + "\n"


if __name__ == "__main__":
    if "--check" in sys.argv:
        sys.exit(0 if OUT.exists() and OUT.read_text(encoding="utf-8") == render() else 1)
    sys.stdout.write(render())
