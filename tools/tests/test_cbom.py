"""`python -m pytest tools/tests -o addopts= -q` (fuera de `tests/`)."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT))
import cbom  # noqa: E402
from qce.core.policy import SUITES, Policy  # noqa: E402

PRIMITIVES = {"drbg", "mac", "block-cipher", "stream-cipher", "signature", "hash", "pke", "xof", "kdf", "key-agree", "kem", "ae", "combiner", "other", "unknown"}


def test_committed_cbom_is_up_to_date():
    assert (ROOT / "benchmarks" / "cbom.cdx.json").read_text(encoding="utf-8") == cbom.render(), "regenera: python tools/cbom.py > benchmarks/cbom.cdx.json"


def test_generation_is_deterministic():
    assert cbom.render() == cbom.render()


def test_structure_matches_what_cyclonedx_1_6_requires_for_crypto_assets():
    b = cbom.build()
    assert b["bomFormat"] == "CycloneDX" and b["specVersion"] == "1.6" and b["serialNumber"].startswith("urn:uuid:")
    refs = [c["bom-ref"] for c in b["components"]]
    assert len(refs) == len(set(refs))
    for c in b["components"]:
        assert c["type"] == "cryptographic-asset" and c["cryptoProperties"]["assetType"] in ("algorithm", "protocol")
        if c["cryptoProperties"]["assetType"] == "algorithm":
            ap = c["cryptoProperties"]["algorithmProperties"]
            assert ap["primitive"] in PRIMITIVES and 0 <= ap["nistQuantumSecurityLevel"] <= 6
        else:
            for cs in c["cryptoProperties"]["protocolProperties"]["cipherSuites"]:
                assert all(a in refs for a in cs["algorithms"]), "una suite apunta a un algoritmo que no está en la lista"


def test_every_suite_of_the_real_policy_registry_is_in_the_cbom_with_its_status():
    names = {c["name"]: c for c in cbom.build()["components"]}
    for sid, s in SUITES.items():
        props = {p["name"]: p["value"] for p in names[sid]["properties"]}
        assert props["qce:policy-status"] == s.status
        assert props["qce:in-default-policy"] == str(sid in Policy().allowed_suites).lower()


def test_quantum_vulnerable_parts_are_flagged_and_pq_parts_have_nist_level_3_or_more():
    b = cbom.build()
    vul = [c["name"] for c in b["components"] if c["cryptoProperties"]["assetType"] == "algorithm"
           and {p["name"]: p["value"] for p in c["properties"]}["qce:quantum-vulnerable"] == "true"]
    assert {"X25519", "Ed25519", "ECDSA-P256"} <= set(vul)  # la PKI del transporte (ECDSA P-256) NO es poscuántica: debe constar
    for c in b["components"]:
        if c["name"].startswith(("ML-KEM", "ML-DSA")):
            assert c["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"] >= 3


def test_forbidden_suite_is_reported_as_forbidden_not_hidden():
    names = {c["name"]: c for c in cbom.build()["components"]}
    assert {p["name"]: p["value"] for p in names["QCE0-X25519-CHACHA"]["properties"]}["qce:policy-status"] == "forbidden"
