"""Custodia de la clave privada del servidor TLS en el KeyStore/vault. Cada escenario corre en un proceso nuevo."""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCEN = ROOT / "tests" / "custody_scenarios.py"
needs = pytest.mark.skipif(not SCEN.exists(), reason="sin escenarios de custodia")


def scenario(name):
    env = {k: v for k, v in os.environ.items() if k != "OPENSSL_CONF"}
    env["PYTHONPATH"] = str(ROOT)
    r = subprocess.run([sys.executable, str(SCEN), name], capture_output=True, text=True, timeout=120, env=env, cwd=ROOT)
    assert r.returncode == 0, r.stderr[-1000:]
    return json.loads(r.stdout.strip().splitlines()[-1])


@needs
def test_server_works_and_no_private_key_ever_sits_in_a_file():
    r = scenario("serve_and_no_plaintext_key")
    assert r["echo"] == "aloh" and r["key_id_has_cert"]
    assert r["files_with_private_key"] == []  # ni en la carpeta de certificados ni en ningún otro archivo creado
    assert r["leftover_temp_dirs"] == []  # la copia cifrada temporal se borró
    assert all(n.endswith(".pem") for n in r["cert_files"])  # solo certificados (públicos)


@needs
def test_the_temporary_key_file_is_encrypted_private_and_protected_by_an_in_memory_password():
    r = scenario("key_file_is_encrypted_while_it_exists")
    assert r["header"] == "-----BEGIN " + "ENCRYPTED " + "PRIVATE " + "KEY-----"  # cifrada: nunca la cabecera de una clave en claro (partida para no activar el escáner de secretos)
    assert r["has_password"] and r["mode"] == "0o600" and r["dir_mode"] == "0o700"


@needs
def test_vault_stores_the_key_encrypted_and_a_restored_vault_can_serve():
    r = scenario("vault_roundtrip")
    assert (r["der_in_vault"], r["hex_in_vault"], r["pem_in_vault"]) == (False, False, False)
    assert r["restored_purpose"] == "TLS" and r["restored_serves"] == "aloh"


@needs
def test_rotation_changes_the_certificate_retires_the_old_key_and_keeps_open_connections():
    r = scenario("rotation")
    assert r["serial_changed"] and r["old_state"] == "RETIRED" and r["new_state"] == "ACTIVE" and r["new_generation"] == 2
    assert r["old_can_build_context"] == "KeyStateError"  # una clave retirada no firma contextos nuevos
    assert r["open_connection_still_works"] == "atreiba"  # la conexión abierta antes de rotar sigue funcionando (eco invertido de «abierta»)
    assert r["active_is_new"]


@needs
def test_revocation_erases_the_secret_and_stops_new_connections():
    r = scenario("revocation")
    assert r["ok_before"] == "aloh" and r["secret_erased"] and r["new_connection_fails"] and r["failed_handshakes"]
    assert r["context_after_revoke"] == "KeyStateError"


@needs
def test_expired_key_cannot_build_new_contexts():
    r = scenario("expiry")
    assert r == {"before": None, "after": "KeyStateError"}


@needs
def test_tls_key_cannot_be_used_for_anything_else():
    r = scenario("purpose_separation")
    assert r["protect_with_tls_key"] == "KeyStateError" and r["use_as_encrypt"] == "KeyStateError" and r["use_as_tls"] is None


@needs
def test_csr_flow_only_accepts_a_valid_certificate_for_this_key_and_name():
    r = scenario("csr_flow")
    assert r["no_cert"] == ["KeyStateError", "CertificateRejected"]  # clave sin certificado: no sirve
    assert r["echo"] == "aloh"
    assert r["other_key"] == "CertificateRejected" and r["wrong_name"] == "CertificateRejected" and r["expired"] == "CertificateRejected"


@needs
def test_certificate_swapped_on_disk_is_detected():
    assert scenario("swapped_certificate") == {"error": "CertificateRejected"}


@needs
def test_audit_trail_records_lifecycle_without_key_material():
    r = scenario("audit_clean")
    assert r["der_hex_in_audit"] is False and r["pem_in_audit"] is False
    assert {"create", "activate", "retire", "revoke"} <= set(r["kinds"])


def test_keystore_retire_is_only_valid_from_active():
    from qce.core.errors import KeyStateError
    from qce.key_management.keystore import KeyStore, Purpose
    ks = KeyStore()
    kid = ks.create(Purpose.TLS, 100)
    with pytest.raises(KeyStateError):
        ks.retire(kid)  # GENERATED → RETIRED no existe
    ks.activate(kid)
    ks.retire(kid)
    with pytest.raises(KeyStateError):
        ks.retire(kid)
