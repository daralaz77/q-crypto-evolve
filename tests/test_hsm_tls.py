"""Servidor TLS 1.3 híbrido con la clave privada en un HSM (SoftHSM de prueba + pkcs11-provider de OpenSSL). Cada escenario corre en un proceso nuevo con su propio token temporal.

Se omiten si falta el proveedor compilado (`~/.qce-hsm-lab/lib/pkcs11.dylib` o QCE_HSM_PROVIDER), SoftHSM, `p11tool` o el `openssl` 3: ver docs/HSM.md y docs/hsm_lab/setup.sh.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))
import hsm_scenarios as HS  # noqa: E402

needs = pytest.mark.skipif(not HS.AVAILABLE, reason="sin el laboratorio HSM (proveedor PKCS#11 compilado, SoftHSM, p11tool y openssl 3)")


def scenario(name, timeout=240):
    env = {k: v for k, v in os.environ.items() if k != "OPENSSL_CONF"} | {"PYTHONPATH": str(ROOT)}
    r = subprocess.run([sys.executable, str(ROOT / "tests" / "hsm_scenarios.py"), name], capture_output=True, text=True, cwd=ROOT, env=env, timeout=timeout)
    assert r.returncode == 0, f"rc={r.returncode} (139 = SIGSEGV)\n{r.stderr[-1200:]}"
    return json.loads(r.stdout.strip().splitlines()[-1])


@needs
def test_a_standard_client_completes_hybrid_tls13_and_the_signature_is_made_by_the_token():
    r = scenario("e2e")
    assert len(r["conexiones"]) == 4
    for c in r["conexiones"]:
        assert c["servidor"]["ok"] and tuple(c["servidor"]["conn"]) == ("TLSv1.3", "X25519MLKEM768", "TLS_AES_256_GCM_SHA384")
        assert c["verificacion_ok"] and c["grupo_cliente"] and c["protocolo"] == "TLSv1.3" and c["firma"] == "rsa_pss_rsae_sha256"
    assert r["cliente_con_otra_ca"]["verificacion_ok"] is False                       # un cliente que no confía en la CA no verifica…
    assert r["despues_del_fallo"] == {"verificacion_ok": True, "servidor_ok": True}    # …y el contexto sigue sirviendo después


@needs
def test_the_private_key_cannot_leave_the_token_and_exportable_keys_are_refused():
    r = scenario("key_never_leaves")
    assert r["p11tool_exporta_privada"] is False
    assert "CKA_NEVER_EXTRACTABLE" in r["flags_privada"] and "CKA_SENSITIVE" in r["flags_privada"]
    assert r["software_rsa_exportable"] is True and r["software_ec_exportable"] is True      # una clave de software SÍ se detecta como exportable
    assert r["clave_exportable_aceptada"] is False and r["clave_exportable_error"] == "PolicyViolation"
    assert r["archivos_con_clave_privada"] == []


@needs
def test_every_misconfiguration_fails_closed_for_its_own_reason_without_falling_back_to_software():
    r = scenario("refusals")
    assert r.pop("base_ok") == "aceptado"
    why = {"uri_no_pkcs11": "URI PKCS#11", "uri_publica": "URI PKCS#11", "uri_sin_tipo": "URI PKCS#11", "objeto_inexistente": "no tiene esa clave privada",
           "token_inexistente": "no tiene esa clave privada", "config_inexistente": "no existe el archivo no.cnf", "cert_inexistente": "no existe el archivo no.pem",
           "sin_proveedor_pkcs11": "no se pudo abrir la clave en el token", "certificado_de_otra_clave": "no corresponde a la clave del token",
           "certificado_basura": "certificado no válido", "suite_no_permitida": "suite no permitida", "grupo_no_permitido": "grupo no permitido"}
    assert set(r) == set(why)
    for k, v in r.items():
        assert v.startswith("PolicyViolation: ") and why[k] in v, (k, v)


@needs
@pytest.mark.parametrize("variant,expected", [("pin_wrong", "PolicyViolation: el token no tiene esa clave privada"), ("pin_missing", "PolicyViolation: el token no tiene esa clave privada"),
                                              ("pin_ok", "aceptado")])
def test_a_wrong_or_missing_pin_is_refused_as_the_first_operation_of_a_process(variant, expected):
    assert scenario(variant)["resultado"].startswith(expected)


@needs
def test_removing_the_key_from_the_token_blocks_new_contexts():
    """Un contexto ya creado conserva su manejador en caché hasta reiniciar el proceso (SoftHSM no invalida manejadores entre procesos): la revocación exige reiniciar el servicio."""
    r = scenario("key_removed")
    assert r["antes_ok"] is True and r["borrado_rc"] == 0 and r["contexto_nuevo"].startswith("PolicyViolation: el token no tiene esa clave privada")


@needs
def test_closing_contexts_does_not_unload_the_module_so_a_later_fork_does_not_crash():
    r = scenario("lifecycle")
    assert r == {"mismo_libctx": True, "b_sirve_tras_cerrar_a": True, "fork_tras_cerrar_todo": True, "reabrir": True}


@needs
def test_every_ssl_object_is_balanced_and_the_library_context_is_created_once_and_never_freed():
    r = scenario("leaks")
    assert r["ctx_creados"] == r["ctx_liberados"] == 6 and r["ssl_creados"] == r["ssl_liberados"] == 5
    assert r["libctx_creados"] == 1 and r["libctx_liberados"] == 0


@needs
def test_the_connection_is_attested_after_the_handshake_with_the_hsm_server_too():
    r = scenario("attest")
    assert r["servidor"]["ok"] is False and r["servidor"]["err"] == "PolicyViolation" and "grupo" in r["servidor"]["msg"]
