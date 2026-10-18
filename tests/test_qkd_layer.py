"""QIL1 (capa interna con clave QKD sobre TLS 1.3): especificación anclada, escenarios hostiles y re-derivación independiente.

Todo corre en procesos nuevos (tests/qkd_layer_scenarios.py): `qkd_layer` importa `tls13` primero y este falla cerrado si `cryptography` ya estaba cargada.
La re-derivación usa SOLO las fórmulas y constantes de docs/QKD_LAYER_SPEC.md y primitivas de `cryptography` directas; no importa nada de qce.
"""
import hashlib
import hmac
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

ROOT = Path(__file__).resolve().parent.parent
SCEN = ROOT / "tests" / "qkd_layer_scenarios.py"
SPEC = (ROOT / "docs" / "QKD_LAYER_SPEC.md").read_text()
NOT_REVIEWED = "NO REVISADA"


def scenario(name, timeout=90):
    env = {k: v for k, v in os.environ.items() if k != "OPENSSL_CONF"}
    env["PYTHONPATH"] = str(ROOT)
    r = subprocess.run([sys.executable, str(SCEN), name], capture_output=True, text=True, timeout=timeout, env=env, cwd=ROOT)
    assert r.returncode == 0, r.stderr[-1200:]
    return json.loads(r.stdout.strip().splitlines()[-1])


def spec_constants() -> dict[str, str]:
    block = re.search(r"```constants\n(.*?)```", SPEC, re.S)
    assert block, "falta el bloque `constants` en la especificación"
    return {k.strip(): v.strip() for k, v in (line.split("=", 1) for line in block.group(1).splitlines() if line.strip())}


# ---- especificación ↔ código ----------------------------------------------------------------------------------
def test_constants_table_matches_code():
    code, spec = scenario("constants"), spec_constants()
    for k, v in spec.items():
        assert str(code[k]) == v, k
    assert set(spec) <= set(code)
    assert code["MAX_PLAINTEXT"] == code["MAX_FRAME"] - 16


def test_every_constant_in_the_table_is_used_by_the_rederivation_or_a_scenario():
    used = {"VERSION", "TH_LABEL", "INFO_CONF", "INFO_C2S", "INFO_S2C", "REC_AAD_LABEL", "ROLE_CLIENT", "ROLE_SERVER", "NONCE_LEN", "TAG_LEN",
            "KEY_ID_MAX", "QKD_KEY_MIN", "QKD_KEY_MAX", "BIND_MIN", "MAX_RECORDS"}
    assert set(spec_constants()) == used


def lp(x: bytes) -> bytes:
    return len(x).to_bytes(4, "big") + x


def test_independent_rederivation_matches_a_real_session():
    c, S = scenario("honest"), spec_constants()
    assert c["version"] == "TLSv1.3" and c["server"] == "ok" and c["th_equal"] and c["reply"] == "dkq aloh"
    hello, accept, confirm, rec_c2s, rec_s2c = (bytes.fromhex(f) for f in c["frames"][-5:])
    key, kid, bind, cert = (bytes.fromhex(c[k]) for k in ("key", "key_id", "bind", "cert"))
    # HELLO: "QIL1" ‖ len(kid) ‖ kid ‖ nc
    assert hello[:4] == S["VERSION"].encode() and hello[4] == len(kid) and hello[5:5 + len(kid)] == kid
    nc = hello[5 + len(kid):]
    ns, ts = accept[:int(S["NONCE_LEN"])], accept[int(S["NONCE_LEN"]):]
    assert len(nc) == len(ns) == int(S["NONCE_LEN"]) and len(ts) == int(S["TAG_LEN"])
    th = hashlib.sha256(lp(S["TH_LABEL"].encode()) + lp(bind) + lp(hashlib.sha256(cert).digest()) + lp(kid) + lp(nc) + lp(ns)).digest()

    def hkdf(info):
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=th, info=info.encode()).derive(key)
    conf, k_c2s, k_s2c = hkdf(S["INFO_CONF"]), hkdf(S["INFO_C2S"]), hkdf(S["INFO_S2C"])
    assert th.hex() == c["th"]
    assert ts == hmac.new(conf, S["ROLE_SERVER"].encode() + th, hashlib.sha256).digest()
    assert confirm == hmac.new(conf, S["ROLE_CLIENT"].encode() + th + ts, hashlib.sha256).digest()
    aad = S["REC_AAD_LABEL"].encode() + th
    assert ChaCha20Poly1305(k_c2s).decrypt((0).to_bytes(12, "big"), rec_c2s, aad) == b"hola qkd"
    assert ChaCha20Poly1305(k_s2c).decrypt((0).to_bytes(12, "big"), rec_s2c, aad) == b"dkq aloh"


def test_every_key_is_separated_by_purpose():
    c, S = scenario("honest"), spec_constants()
    th, key = bytes.fromhex(c["th"]), bytes.fromhex(c["key"])
    outs = {HKDF(algorithm=hashes.SHA256(), length=32, salt=th, info=S[i].encode()).derive(key) for i in ("INFO_CONF", "INFO_C2S", "INFO_S2C")}
    assert len(outs) == 3


# ---- comportamiento hostil -----------------------------------------------------------------------------------------
def test_key_is_single_use_and_wrong_or_unknown_keys_are_rejected():
    r = scenario("reuse_and_wrong_key")
    assert r["uso_1_cliente"] == "ok" and r["uso_1_servidor"] == "ok"
    assert r["uso_2_cliente"] != "ok" and r["uso_2_servidor"] == "AuthenticationFailure"        # el servidor ya no tiene la clave
    assert r["clave_equivocada_cliente"] == "AuthenticationFailure"                            # el cliente nunca acepta un servidor sin la clave
    assert r["id_desconocido_servidor"] == "AuthenticationFailure" and r["id_desconocido_cliente"] != "ok"


def test_server_rejects_a_client_tag_made_without_the_key_and_a_malformed_hello_does_not_burn_the_key():
    r = scenario("bad_client_tag")
    assert r["accept_len"] == 64 and r["servidor"] == "AuthenticationFailure"
    assert r["hello_malformado_servidor"] == "MalformedMessage" and r["clave_sigue_disponible"] is True
    assert r["clave_corta_servidor"] == r["clave_larga_servidor"] == "PolicyViolation"    # la fuente entrega material fuera de rango


def test_rogue_certificate_mitm_cannot_complete_the_layer():
    r = scenario("rogue_mitm")
    assert r["cliente"] == "AuthenticationFailure"          # el cliente detecta que el servidor real no estaba en SU sesión TLS
    assert r["servidor_real"] != "ok" and r["retransmision"] != "completo"


def test_layer_refuses_to_open_without_a_usable_tls13_binding_or_key():
    r = scenario("binding_checks")
    for k in ("tls12", "sin_binding", "binding_corto", "sin_certificado", "clave_corta", "clave_larga", "server_sin_binding"):
        assert r[k] == "PolicyViolation", k
    for k in ("id_vacio", "id_largo"):
        assert r[k] == "MalformedMessage", k
    for k in ("binding_minimo_ok", "clave_minima_ok", "clave_maxima_ok", "id_maximo_ok", "id_minimo_ok"):    # en el límite sí pasan y llegan a esperar la respuesta
        assert r[k] == "OSError", k
    nc = "07" * 32
    assert r["hello_enviado"] == "51494c31" + "0c" + KID_HEX + nc


KID_HEX = b"qkd-key-0001".hex()


def test_hello_parsing_is_strict():
    r = scenario("hello_parsing")
    assert r["ok"] == "ok" and r["id_maximo"] == "ok" and r["roundtrip"] is True
    for k in ("version_mala", "corto", "id_cero", "id_demasiado_largo", "falta_un_byte", "sobra_un_byte"):
        assert r[k] == "MalformedMessage", k


def test_record_layer_rejects_tampering_replay_reflection_reordering_and_other_sessions():
    r = scenario("records")
    assert (r["ida"], r["vuelta"], r["segundo"], r["cinco"], r["ultimo"]) == ("uno", "dos", "tres", "cinco", "ultimo")
    for k in ("manipulado", "repeticion", "reflexion", "otro_transcript", "reordenado"):
        assert r[k] == "AuthenticationFailure", k
    assert r["contador_agotado_escritura"] == r["contador_agotado_lectura"] == "KeyStateError"
    assert r["demasiado_grande"] == "MalformedMessage" and r["maximo_ok"] == "ok" and r["maximo_leido"] == 1048560


def test_integration_with_the_key_broker_consumes_once_and_fails_closed():
    r = scenario("broker")
    assert r["eco"] == "rekorb noc" and r["servidor"] == "ok"
    assert r["reutilizar_id"] is None and r["id_desconocido"] is None and r["id_no_ascii"] is None and r["consumidor_no_autorizado"] is None
    assert r["enlace_en_cuarentena"] is None and r["cuarentena_registrada"] is True       # QBER de espionaje: sin clave y con el enlace bloqueado


def test_nonces_are_fresh_in_every_session():
    r = scenario("nonce_freshness")
    assert r["hellos"] == 2 and r["nc_distintos"] and r["ns_distintos"] and r["th_distintos"] and r["nc_no_cero"] and r["ns_no_cero"]


def test_client_rejects_an_accept_of_the_wrong_length():
    r = scenario("bad_accept")
    assert set(r.values()) == {"MalformedMessage"} and len(r) == 3


# ---- declaración de estado ------------------------------------------------------------------------------------------
def test_every_document_declares_the_layer_as_not_reviewed():
    assert NOT_REVIEWED in SPEC and "NO REVISADO" in (ROOT / "formal" / "qil1.spthy").read_text()
    assert NOT_REVIEWED in (ROOT / "qce" / "transport" / "qkd_layer.py").read_text()
