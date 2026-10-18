"""Transporte TLS 1.3 con X25519MLKEM768 obligatorio. Cada escenario corre en un proceso nuevo (ver tests/tls_scenarios.py)."""
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCEN = ROOT / "tests" / "tls_scenarios.py"
def find_openssl():
    """El primer openssl que soporte el grupo híbrido (el de macOS es LibreSSL y no lo soporta; las puertas corren con un PATH mínimo)."""
    for cand in (shutil.which("openssl"), "/opt/homebrew/bin/openssl", "/opt/homebrew/opt/openssl@3/bin/openssl", "/usr/local/bin/openssl"):
        if cand and Path(cand).exists():
            out = subprocess.run([cand, "list", "-kem-algorithms"], capture_output=True, text=True).stdout
            if "X25519MLKEM768" in out:
                return cand
    return None


OPENSSL = find_openssl()
needs_tls = pytest.mark.skipif(not SCEN.exists(), reason="sin escenarios TLS")


def clean_env():
    env = {k: v for k, v in os.environ.items() if k != "OPENSSL_CONF"}  # que nada heredado oculte un fallo
    env["PYTHONPATH"] = str(ROOT)
    return env


def scenario(name, *args, timeout=60):
    r = subprocess.run([sys.executable, str(SCEN), name, *args], capture_output=True, text=True, timeout=timeout, env=clean_env(), cwd=ROOT)
    assert r.returncode == 0, r.stderr[-800:]
    return json.loads(r.stdout.strip().splitlines()[-1])


def openssl_supports(pattern):
    return OPENSSL is not None


@needs_tls
def test_attestation_passes_in_a_properly_started_process():
    assert scenario("attest") == {"attested": True}


@needs_tls
def test_attestation_fails_closed_when_cryptography_was_imported_first():
    out = scenario("misconfigured")
    assert out == {"raised": True, "mentions_import_order": True}  # sin degradación silenciosa


@needs_tls
def test_encrypted_exchange_uses_tls13_with_a_strong_aead():
    out = scenario("echo")
    assert out["version"] == "TLSv1.3" and out["cipher"] in ("TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256")
    assert out["echo"] == "ocitnaucsop aloh"


@needs_tls
def test_contexts_are_hardened():
    p = scenario("context_properties")
    assert p == {"server_tickets": 0, "server_min": "TLSv1_3", "client_min": "TLSv1_3", "client_verify": "CERT_REQUIRED",
                 "client_hostname_check": True, "server_verify": "CERT_NONE"}


@needs_tls
@pytest.mark.parametrize("name", ["wrong_hostname", "untrusted_ca", "expired", "tls12_client", "classical_group_client"])
def test_connection_is_rejected(name):
    out = scenario(name)
    assert out["ok"] is False, out  # nombre incorrecto, CA no fiable, certificado caducado, TLS 1.2 o solo curva clásica


@needs_tls
def test_mutual_authentication_requires_a_client_certificate():
    missing = scenario("mtls_missing")
    assert missing["ok"] is False and missing["handler_saw"] == []  # el manejador nunca vio a un cliente sin certificado
    ok = scenario("mtls_ok")
    assert ok["ok"] is True and ok["handler_saw"] == ["cliente-1"]  # con certificado: pasa, y el servidor ve su identidad


@needs_tls
def test_frame_limits_are_enforced():
    out = scenario("frames")
    assert out == {"send_too_big": "MalformedMessage", "small_reply": "OK", "oversized_reply": None}


@needs_tls
@pytest.mark.skipif(not openssl_supports("X25519MLKEM768"), reason="el openssl del sistema no soporta X25519MLKEM768")
def test_third_party_client_confirms_the_negotiated_group_and_classical_offers_fail():
    srv = subprocess.Popen([sys.executable, str(SCEN), "serve", "25"], stdout=subprocess.PIPE, text=True, env=clean_env(), cwd=ROOT)
    try:
        info = json.loads(srv.stdout.readline())
        time.sleep(0.5)

        def s_client(*flags):  # el aviso de fallo sale por stderr: se juntan los dos flujos
            r = subprocess.run([OPENSSL, "s_client", "-connect", f"127.0.0.1:{info['port']}", "-CAfile", info["ca"], "-verify_hostname", "localhost", *flags],
                               input="", capture_output=True, text=True, timeout=20)
            return r.stdout + r.stderr

        good = s_client("-tls1_3", "-groups", "X25519MLKEM768")
        assert "Negotiated TLS1.3 group: X25519MLKEM768" in good and "Verification: OK" in good
        for classical in ("X25519", "P-256"):
            bad = s_client("-tls1_3", "-groups", classical)
            assert "Negotiated TLS1.3 group: <NULL>" in bad and "handshake failure" in bad.lower(), classical
        old = s_client("-tls1_2")
        assert "Cipher is (NONE)" in old and "alert protocol version" in old.lower()  # TLS 1.2: sin cifrado negociado y con aviso de versión de protocolo
    finally:
        srv.kill()


@needs_tls
@pytest.mark.skipif(not openssl_supports("X25519MLKEM768") or not OPENSSL, reason="se necesita openssl con ML-DSA")
def test_post_quantum_certificate_ml_dsa_65_works_with_the_hybrid_group(tmp_path):
    r = subprocess.run([OPENSSL, "req", "-x509", "-newkey", "ML-DSA-65", "-nodes", "-keyout", str(tmp_path / "k.pem"), "-out", str(tmp_path / "c.pem"),
                        "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost"], capture_output=True, text=True)
    if r.returncode != 0:
        pytest.skip("este openssl no genera certificados ML-DSA-65")
    out = scenario("mldsa", str(tmp_path / "c.pem"), str(tmp_path / "k.pem"))
    assert out["ok"] is True and out["version"] == "TLSv1.3"
    text = subprocess.run([OPENSSL, "x509", "-in", str(tmp_path / "c.pem"), "-noout", "-text"], capture_output=True, text=True).stdout
    assert "Signature Algorithm: ML-DSA-65" in text  # autenticación poscuántica real, no solo intercambio de claves
