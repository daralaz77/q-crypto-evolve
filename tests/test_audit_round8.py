"""Ronda 8 de auditoría (2026-11-18): superar los límites declarados en la ronda 7.

1. El tope de conexiones era GLOBAL: un solo origen lo llenaba y dejaba fuera a todos. Ahora también hay tope POR ORIGEN (`ConnectionGuard`).
2. `min_crl_number` lo fijaba quien despliega. Ahora `CrlPin` recuerda por emisor el número más alto visto y solo permite avanzar.
3. Solo se comprobaba la hoja. Ahora `crl_file=[...]` comprueba la cadena entera (una CRL por cada CA que emite) y detecta una CA intermedia revocada.
4. El plazo por operación del KME emulado no tenía prueba: ahora es configurable (`io_timeout`) y probado.
"""
# ruff: noqa: F811
import datetime as dt
import json
import os
import socket
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest
from cryptography import x509

from qce.core.ratelimit import ConnectionGuard
from qce.transport import pki
from qce.transport.crl import CrlPin, CrlRejected, check_crl
from tests.test_etsi014 import env  # noqa: F401, F811  (es un fixture)

ROOT = Path(__file__).resolve().parent.parent
SCEN = ROOT / "tests" / "dos_crl_scenarios.py"


def scenario(name, timeout=90):
    child_env = {k: v for k, v in os.environ.items() if k != "OPENSSL_CONF"}
    child_env["PYTHONPATH"] = str(ROOT)
    r = subprocess.run([sys.executable, str(SCEN), name], capture_output=True, text=True, timeout=timeout, env=child_env, cwd=ROOT)
    assert r.returncode == 0, r.stderr[-800:]
    return json.loads(r.stdout.strip().splitlines()[-1])


# --- 1. tope por origen ---------------------------------------------------------------------------------------------------------------------------------

def test_one_origin_cannot_fill_the_server_and_lock_out_the_rest():
    r = scenario("origin_cap")
    assert r["extra_closed_in"] is not None and r["extra_closed_in"] < 1   # la tercera del MISMO origen se corta al instante
    assert r["rejected_origin"] == 1 and r["rejected_busy"] == 0           # por el tope de origen, no por el global (que está lejos)
    assert r["served_after_release"]


def test_the_guard_limits_each_origin_but_lets_the_others_in():
    g = ConnectionGuard(max_total=10, max_per_origin=2)
    assert [g.acquire("10.0.0.1") for _ in range(3)] == [None, None, "origin"]
    assert g.acquire("10.0.0.2") is None                                   # otro origen sigue entrando
    assert g.active == 3 and g.tracked_origins == 2


def test_the_global_cap_wins_and_is_reported_as_busy():
    g = ConnectionGuard(max_total=2, max_per_origin=5)
    assert g.acquire("a") is None and g.acquire("b") is None
    assert g.acquire("c") == "busy"
    assert g.acquire("a") == "busy"                                        # aunque «a» no llegó a su tope: el global manda


def test_releasing_gives_the_slot_back_and_forgets_idle_origins():
    g = ConnectionGuard(max_total=5, max_per_origin=1)
    assert g.acquire("x") is None and g.acquire("x") == "origin"
    g.release("x")
    assert g.tracked_origins == 0 and g.active == 0                        # memoria acotada: solo orígenes con conexiones activas
    assert g.acquire("x") is None
    g.release("x")
    g.release("x")                                                         # liberar de más no hace negativo el contador
    g.release("nunca-visto")
    assert g.active == 0
    assert g.acquire("x") is None and g.acquire("y") is None               # y no «regala» huecos de más
    assert g.acquire("z") is None


def test_ipv6_addresses_of_the_same_network_share_one_origin():
    g = ConnectionGuard(max_total=10, max_per_origin=2)
    assert g.acquire("2001:db8:1:2::1") is None and g.acquire("2001:db8:1:2::ffff") is None
    assert g.acquire("2001:db8:1:2:aaaa::9") == "origin"                   # mismo /64
    assert g.acquire("2001:db8:1:3::1") is None                            # otro /64
    g2 = ConnectionGuard(max_total=10, max_per_origin=1)
    assert g2.acquire("::ffff:192.0.2.7") is None and g2.acquire("192.0.2.7") == "origin"   # IPv4 asignada a IPv6 = su IPv4


def test_without_a_per_origin_cap_only_the_global_one_applies():
    g = ConnectionGuard(max_total=3)
    assert [g.acquire("a") for _ in range(4)] == [None, None, None, "busy"]


@pytest.mark.parametrize("total,per", [(0, None), (-1, 1), (1, 0), (1, -3)])
def test_the_guard_refuses_non_positive_limits(total, per):
    with pytest.raises(ValueError):
        ConnectionGuard(total, per)


def test_the_psk_server_caps_each_origin():
    from tests.test_tls13_psk import HAVE_LIB, KEY, KID, client
    if not HAVE_LIB:
        pytest.skip("sin OpenSSL ≥ 3.5 utilizable")
    import threading
    from qce.qkd.sources import OneTimeKeys
    from qce.transport import tls13_psk as P
    gate = threading.Event()
    store = OneTimeKeys({KID: KEY, b"kid-2": KEY})
    srv = P.PskServer(store, lambda c: gate.wait(10), timeout=5.0, max_connections=10, max_per_origin=1).start()
    try:
        first = client(srv)
        time.sleep(0.3)
        extra = socket.create_connection(("127.0.0.1", srv.port))
        extra.settimeout(3)
        assert extra.recv(1) == b""
        extra.close()
        assert srv.rejected_origin == 1 and srv.rejected_busy == 0
        gate.set()
        first.close()
        time.sleep(0.5)
        assert client(srv, b"kid-2") is not None
    finally:
        gate.set()
        srv.close()


def test_the_kme_caps_each_origin(env):
    from qce.qkd.etsi014 import HttpsTransport
    from qce.qkd.etsi014_emulator import EmulatedKME
    from tests.test_etsi014 import MASTER, SLAVE, client_ctx, server_ctx
    kme = EmulatedKME(server_ctx(env.scert, env.skey, env.ca), MASTER, SLAVE, max_connections=10, max_per_origin=1).start()
    holder = socket.create_connection(("127.0.0.1", kme.port))
    try:
        time.sleep(0.3)
        extra = socket.create_connection(("127.0.0.1", kme.port))
        extra.settimeout(3)
        assert extra.recv(1) == b""
        extra.close()
        assert kme.rejected_origin == 1 and kme.rejected_busy == 0
        holder.close()
        time.sleep(0.5)
        cert, key = env.certs[MASTER]
        ok = HttpsTransport("127.0.0.1", kme.port, client_ctx(env.ca, cert, key), timeout=5.0, pin_required=False)
        assert ok.request("GET", f"/api/v1/keys/{SLAVE}/status")[0] == 200
    finally:
        holder.close()
        kme.close()


# --- 2. plazo por operación del KME -----------------------------------------------------------------------------------------------------------------------

def test_a_connection_that_stalls_is_dropped_after_the_io_timeout_and_gives_its_slot_back(env):
    from qce.qkd.etsi014 import HttpsTransport
    from qce.qkd.etsi014_emulator import EmulatedKME
    from tests.test_etsi014 import MASTER, SLAVE, client_ctx, server_ctx
    kme = EmulatedKME(server_ctx(env.scert, env.skey, env.ca), MASTER, SLAVE, max_connections=1, io_timeout=1.0).start()
    mute = socket.create_connection(("127.0.0.1", kme.port))              # ocupa el único hueco y no dice nada
    try:
        time.sleep(0.3)
        busy = socket.create_connection(("127.0.0.1", kme.port))
        busy.settimeout(3)
        assert busy.recv(1) == b""                                         # mientras calla, no hay sitio
        busy.close()
        mute.settimeout(4)
        t0 = time.monotonic()
        assert mute.recv(1) == b""                                         # el servidor la corta por su cuenta
        assert time.monotonic() - t0 < 3
        time.sleep(0.3)
        cert, key = env.certs[MASTER]
        ok = HttpsTransport("127.0.0.1", kme.port, client_ctx(env.ca, cert, key), timeout=5.0, pin_required=False)
        assert ok.request("GET", f"/api/v1/keys/{SLAVE}/status")[0] == 200   # y el hueco quedó libre
    finally:
        mute.close()
        kme.close()


def test_the_kme_limits_must_be_positive(env):
    from qce.qkd.etsi014_emulator import EmulatedKME
    from tests.test_etsi014 import MASTER, SLAVE, server_ctx
    for kw in ({"max_connections": 0}, {"max_per_origin": 0}):
        with pytest.raises(ValueError):
            EmulatedKME(server_ctx(env.scert, env.skey, env.ca), MASTER, SLAVE, **kw)


# --- 3. ancla local del número de CRL --------------------------------------------------------------------------------------------------------------------

@pytest.fixture
def lab(tmp_path):
    ca, ck, cc = pki.issue_ca(tmp_path)
    return tmp_path, ca, ck, cc


def test_the_pin_remembers_the_highest_number_and_only_lets_it_advance(lab):
    d, ca, ck, cc = lab
    pin = CrlPin(d / "pin" / "crl-pin.json")
    assert check_crl(pki.issue_crl(d, ck, cc, [], number=5, name="a.pem"), ca, pin=pin) == 5
    with pytest.raises(CrlRejected, match="retroceso"):
        check_crl(pki.issue_crl(d, ck, cc, [], number=4, name="b.pem"), ca, pin=pin)
    assert check_crl(pki.issue_crl(d, ck, cc, [], number=5, name="c.pem"), ca, pin=pin) == 5     # el mismo número es válido
    assert check_crl(pki.issue_crl(d, ck, cc, [], number=9, name="d.pem"), ca, pin=pin) == 9
    with pytest.raises(CrlRejected, match="retroceso"):
        check_crl(pki.issue_crl(d, ck, cc, [], number=5, name="e.pem"), ca, pin=pin)             # ya no se puede volver a la 5
    assert json.loads((d / "pin" / "crl-pin.json").read_text()) == {"CN=QCE lab CA": 9}


def test_the_pin_survives_a_restart(lab):
    d, ca, ck, cc = lab
    check_crl(pki.issue_crl(d, ck, cc, [], number=7), ca, pin=CrlPin(d / "pin.json"))
    with pytest.raises(CrlRejected, match="retroceso"):
        check_crl(pki.issue_crl(d, ck, cc, [], number=6, name="viejo.pem"), ca, pin=CrlPin(d / "pin.json"))   # otro objeto = otro proceso


def test_a_list_that_fails_any_other_check_never_raises_the_floor(lab, tmp_path_factory):
    d, ca, ck, cc = lab
    pin = CrlPin(d / "pin.json")
    check_crl(pki.issue_crl(d, ck, cc, [], number=3), ca, pin=pin)
    d2 = tmp_path_factory.mktemp("falsa")
    _ca2, ck2, _cc2 = pki.issue_ca(d2)                                      # mismo nombre, OTRA clave
    with pytest.raises(CrlRejected, match="firma"):
        check_crl(pki.issue_crl(d2, ck2, cc, [], number=999), ca, pin=pin)
    expired = pki.issue_crl(d, ck, cc, [], number=50, name="x.pem")
    with pytest.raises(CrlRejected, match="caducada"):
        check_crl(expired, ca, pin=pin, now=dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=3))
    assert json.loads((d / "pin.json").read_text()) == {"CN=QCE lab CA": 3}  # el suelo no se movió


def test_the_pin_keeps_a_separate_floor_for_each_issuer(lab, tmp_path_factory):
    d, ca, ck, cc = lab
    d2 = tmp_path_factory.mktemp("otra")
    ca2, ck2, cc2 = pki.issue_ca(d2, cn="Otra CA")
    pin = CrlPin(d / "pin.json")
    check_crl(pki.issue_crl(d, ck, cc, [], number=10), ca, pin=pin)
    assert check_crl(pki.issue_crl(d2, ck2, cc2, [], number=2), ca2, pin=pin) == 2   # el 2 de OTRA CA no es un retroceso del 10 de la primera
    assert json.loads((d / "pin.json").read_text()) == {"CN=Otra CA": 2, "CN=QCE lab CA": 10}


def test_the_pin_file_is_private_and_unreadable_pins_fail_closed(lab):
    d, ca, ck, cc = lab
    p = d / "pin.json"
    check_crl(pki.issue_crl(d, ck, cc, [], number=1), ca, pin=CrlPin(p))
    assert stat.S_IMODE(p.stat().st_mode) == 0o600
    for bad in ("{no es json", "[1, 2]", '{"a": -1}', '{"a": true}', '{"a": "1"}', '{"a": 1.5}', '{"a": null}'):
        p.write_text(bad)
        with pytest.raises(CrlRejected, match="no se puede leer"):
            check_crl(pki.issue_crl(d, ck, cc, [], number=2, name="z.pem"), ca, pin=CrlPin(p))
    p.write_bytes(b"\xff\xfe")
    with pytest.raises(CrlRejected, match="no se puede leer"):
        CrlPin(p).check("CN=x", 1)
    p.unlink()
    p.mkdir()                                                              # una ruta que existe pero no se puede leer como archivo (OSError)
    with pytest.raises(CrlRejected, match="no se puede leer"):
        CrlPin(p).check("CN=x", 1)


def test_a_list_without_number_cannot_be_pinned(lab):
    d, ca, ck, cc = lab
    now = dt.datetime.now(dt.timezone.utc)
    b = x509.CertificateRevocationListBuilder().issuer_name(cc.subject).last_update(now - dt.timedelta(minutes=1)).next_update(now + dt.timedelta(days=1))
    nonum = d / "nonum.pem"
    nonum.write_bytes(b.sign(ck, pki.signing_hash(ck)).public_bytes(pki.serialization.Encoding.PEM))
    with pytest.raises(CrlRejected, match="no lleva número"):
        check_crl(nonum, ca, pin=CrlPin(d / "pin.json"))
    assert not (d / "pin.json").exists()


def test_the_pin_in_a_context_ratchets_without_a_manual_minimum():
    r = scenario("crl_pin")
    assert r["first"] == "ok" and r["newer"] == "ok" and r["same"] == "ok"
    assert r["older"] == "CrlRejected"                                     # sin que nadie fijara un mínimo
    assert r["forged_high"] == "CrlRejected" and r["floor_after_forgery"] == {"CN=QCE lab CA": 6}
    assert r["still_older_after_forgery"] == "CrlRejected"
    assert r["pin_without_crl"] == "TransportMisconfigured" and r["server_pin_without_mtls"] == "TransportMisconfigured"


# --- 4. cadena entera ---------------------------------------------------------------------------------------------------------------------------------

def test_the_whole_chain_is_checked_when_a_list_of_crls_is_given():
    r = scenario("chain_crl")
    assert r["both_empty"] == "gnip"                                       # cadena sana: pasa
    assert r["leaf_revoked"] == "SSLCertVerificationError"
    assert r["intermediate_revoked"] == "SSLCertVerificationError"         # lo que el modo hoja no veía
    assert r["root_crl_missing"] == "SSLCertVerificationError"             # falta la CRL de una CA de la cadena: falla cerrado
    assert r["leaf_mode_misses_intermediate"] == "gnip"                    # el modo hoja (una sola CRL) sigue sin verlo: por eso existe el modo cadena
    assert r["issuer_not_in_trust"] == "CrlRejected"                       # la CRL de una intermedia que no está en `ca_file` no se acepta
    assert r["chain_with_min_number"] == "TransportMisconfigured"          # un único mínimo no sirve para varios emisores
    assert r["empty_list"] == "TransportMisconfigured"


def test_the_lab_pki_can_issue_an_intermediate_that_only_signs_leaves(tmp_path):
    ca, ck, cc = pki.issue_ca(tmp_path, path_length=1)
    ip, ik, ic = pki.issue_intermediate(tmp_path, ck, cc)
    assert ic.issuer == cc.subject and ic.subject != cc.subject
    bc = ic.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert bc.ca and bc.path_length == 0
    assert cc.extensions.get_extension_for_class(x509.BasicConstraints).value.path_length == 1
    default_ca = x509.load_pem_x509_certificate(pki.issue_ca(tmp_path / "x", ) [2].public_bytes(pki.serialization.Encoding.PEM)) if (tmp_path / "x").mkdir() is None else None
    assert default_ca.extensions.get_extension_for_class(x509.BasicConstraints).value.path_length == 0   # el valor por defecto no cambia


def test_releasing_an_ipv6_connection_frees_the_slot_of_its_network():
    g = ConnectionGuard(max_total=5, max_per_origin=1)
    assert g.acquire("2001:db8:1:2::1") is None and g.acquire("2001:db8:1:2::2") == "origin"
    g.release("2001:db8:1:2::1")                                           # se libera con la MISMA agrupación con la que se admitió
    assert g.active == 0 and g.tracked_origins == 0
    assert g.acquire("2001:db8:1:2::3") is None
