"""Custodia de la clave privada del servidor TLS en el KeyStore/vault. Cada escenario corre en un proceso nuevo."""
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCEN = ROOT / "tests" / "custody_scenarios.py"
needs = pytest.mark.skipif(not SCEN.exists(), reason="sin escenarios de custodia")


def scenario(name):
    env = {k: v for k, v in os.environ.items() if k != "OPENSSL_CONF"}
    env["PYTHONPATH"] = str(ROOT)
    with tempfile.TemporaryDirectory(prefix="qce-scn-tmp-") as own_tmp:  # INC-0034: temporal PROPIO; el escenario cuenta sus `qce-key-*` aquí, no en el /tmp compartido
        env["TMPDIR"] = own_tmp
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


@needs
def test_automatic_rotation_renews_before_expiry_retires_the_old_key_and_updates_the_server():
    r = scenario("auto_rotation")
    assert r["not_due"] is None                                   # con tiempo de sobra no rota
    assert r["rotated_at_limit"] and r["serial_changed"] and r["echo2"] == "aloh"       # justo en el límite sí, y el servidor ya sirve el certificado nuevo
    assert r["again_is_none"] and r["old_state"] == "RETIRED" and r["second_state"] == "RETIRED"   # recién rotada no vuelve a rotar; cada rotación retira la anterior
    assert r["rotated_after_expiry"] and r["serial3_changed"] and r["echo3"] == "aloh"   # con la clave activa ya caducada también se recupera
    assert r["from_nothing_serves"] and r["recovers_after_revoke"]                      # y sin ninguna clave activa (inicio o tras revocar) provisiona una


@needs
def test_a_revoked_certificate_is_rejected_by_clients_that_check_the_crl_and_a_missing_crl_fails_closed():
    r = scenario("revocation_crl")
    assert r["ok_before"] == "aloh"                               # con una CRL vacía el certificado sirve
    assert r["revoked"] == "SSLCertVerificationError"             # revocado y listado: rechazado aunque el servidor siga ofreciéndolo
    assert r["without_crl_still_accepted"] == "aloh"              # sin comprobar la CRL se acepta: por eso la comprobación es explícita (límite declarado)
    assert r["foreign_crl"] == "SSLCertVerificationError"         # una CRL que no es de la CA del certificado = no hay CRL válida: falla cerrado
    assert r["crl_entries"] == 1


@needs
def test_inc_0034_other_processes_creating_key_dirs_in_the_shared_tmp_do_not_fake_a_leftover():
    """INC-0034: la prueba de «no queda copia temporal» mide un directorio temporal COMPARTIDO; otro proceso paralelo que cree un `qce-key-*` en
    esa ventana aparecía como sobrante. Aquí un hilo crea y borra directorios `qce-key-*` en el temporal compartido MIENTRAS corre el escenario."""
    stop, made = threading.Event(), []

    def noisy_neighbour():
        base = Path(tempfile.gettempdir())
        n = 0
        while not stop.is_set():
            d = base / f"qce-key-race{os.getpid()}x{n}"
            d.mkdir(exist_ok=True)
            made.append(d)
            n += 1
            time.sleep(0.01)

    t = threading.Thread(target=noisy_neighbour, daemon=True)
    t.start()
    try:
        r = scenario("serve_and_no_plaintext_key")
    finally:
        stop.set()
        t.join()
        for d in made:
            d.rmdir()
    assert made, "el vecino ruidoso no llegó a crear ningún directorio: la prueba no probó nada"
    assert r["leftover_temp_dirs"] == []
