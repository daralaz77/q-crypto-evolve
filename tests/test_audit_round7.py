"""Ronda 7 de auditoría (2026-11-18): agotamiento de recursos del transporte y revocación con CRL.

1. `TlsServer`: sin tope de conexiones simultáneas; un byte cada pocos segundos mantenía vivo el apretón indefinidamente (el plazo era por operación); un error transitorio de
   `accept` (sin descriptores) terminaba el servidor en silencio. `PskServer`: lo mismo salvo el plazo, que ya era total.
2. `server_context` no tenía CRL: con autenticación mutua, un certificado de CLIENTE revocado entraba. Y ninguna de las dos partes comprobaba que la CRL fuera de la CA,
   estuviera vigente ni retrocediera: se podía poner una CRL antigua (todavía vigente, sin las revocaciones recientes) en su lugar.
3. El KME emulado hacía el apretón TLS en el único hilo de aceptación: un cliente que conectaba y no decía nada lo bloqueaba entero.
"""
# ruff: noqa: F811
import datetime as dt
import json
import os
import socket
import ssl
import subprocess
import sys
import time
from pathlib import Path

import pytest
from cryptography import x509

from qce.transport import crl as crlmod
from qce.transport import pki
from qce.transport.crl import CrlRejected, check_crl
from tests.test_etsi014 import env  # noqa: F401, F811  (es un fixture)

ROOT = Path(__file__).resolve().parent.parent
SCEN = ROOT / "tests" / "dos_crl_scenarios.py"


def scenario(name, timeout=90):
    child_env = {k: v for k, v in os.environ.items() if k != "OPENSSL_CONF"}
    child_env["PYTHONPATH"] = str(ROOT)
    r = subprocess.run([sys.executable, str(SCEN), name], capture_output=True, text=True, timeout=timeout, env=child_env, cwd=ROOT)
    assert r.returncode == 0, r.stderr[-800:]
    return json.loads(r.stdout.strip().splitlines()[-1])


# --- 1. servidor TLS ------------------------------------------------------------------------------------------------------------------------------------

def test_a_client_that_drips_bytes_cannot_keep_a_handshake_alive():
    r = scenario("slowloris")
    assert r["closed_in"] is not None and r["closed_in"] < 3          # plazo TOTAL de 1 s: lo corta aunque no pase más de 0,3 s sin recibir un byte
    assert r["failed"] == 1 and r["ok_after"] == "gnip"                # y el servidor sigue sirviendo a quien sí habla TLS


def test_connections_beyond_the_cap_are_closed_without_a_thread_and_the_slot_is_given_back():
    r = scenario("busy_cap")
    assert r["extra_closed_in"] is not None and r["extra_closed_in"] < 1   # la tercera se corta al instante (sin apretón)
    assert r["rejected_busy"] == 1 and r["rejected_after"] == 1            # las dos primeras ocupan los huecos
    assert r["served_after_release"]                                       # al terminar sus manejadores el hueco vuelve


def test_an_authenticated_connection_has_a_maximum_lifetime():
    r = scenario("lifetime")
    assert r["closed_in"] is not None and r["closed_in"] < 4


def test_a_transient_accept_error_does_not_kill_the_server():
    r = scenario("accept_survives")
    assert r["failures_injected"] == 2 and r["echo"] == "gnip" and r["alive"]
    assert r["stopped_after_close"]                                        # y cerrar el servidor sí lo detiene (no gira en vacío)


def test_server_limits_must_be_positive():
    r = scenario("crl_args")
    assert [r[k] for k in ("bad_limits", "bad_origin_limit", "bad_handshake_timeout", "bad_lifetime")] == ["ValueError"] * 4


# --- 2. CRL ---------------------------------------------------------------------------------------------------------------------------------------------

def test_a_revoked_client_certificate_is_rejected_by_a_server_that_checks_the_crl():
    r = scenario("mtls_crl")
    assert r["good"] == "gnip"
    assert r["revoked"] != "gnip" and r["revoked"] in ("SSLError", "SSLCertVerificationError", "MalformedMessage", "ConnectionResetError", "BrokenPipeError")
    assert r["without_crl"] == "gnip"                                      # sin CRL el revocado entraba (límite declarado: la comprobación es explícita)


def test_crl_arguments_fail_closed_when_they_make_no_sense_or_the_list_goes_backwards():
    r = scenario("crl_args")
    assert r["server_crl_without_client_ca"] == "TransportMisconfigured"
    assert r["client_min_without_crl"] == "TransportMisconfigured" and r["server_min_without_crl"] == "TransportMisconfigured"
    assert r["client_rollback"] == "CrlRejected" and r["server_rollback"] == "CrlRejected"
    assert r["client_ok"] == "ok"
    assert r["server_min_without_mtls"] == "TransportMisconfigured"


@pytest.fixture
def lab(tmp_path):
    ca, ck, cc = pki.issue_ca(tmp_path)
    return tmp_path, ca, ck, cc


def test_check_crl_returns_the_number_of_a_good_list(lab):
    d, ca, ck, cc = lab
    assert check_crl(pki.issue_crl(d, ck, cc, [], number=9), ca) == 9
    assert check_crl(pki.issue_crl(d, ck, cc, [], number=9), ca, min_number=9) == 9


def test_check_crl_refuses_a_list_that_goes_backwards(lab):
    d, ca, ck, cc = lab
    old = pki.issue_crl(d, ck, cc, [], number=4)
    with pytest.raises(CrlRejected, match="retroceso"):
        check_crl(old, ca, min_number=5)


def test_check_crl_refuses_a_list_without_number_when_a_minimum_is_required(lab):
    d, ca, ck, cc = lab
    now = dt.datetime.now(dt.timezone.utc)
    b = (x509.CertificateRevocationListBuilder().issuer_name(cc.subject).last_update(now - dt.timedelta(minutes=1)).next_update(now + dt.timedelta(days=1)))
    nonum = d / "nonum.pem"
    nonum.write_bytes(b.sign(ck, pki.signing_hash(ck)).public_bytes(pki.serialization.Encoding.PEM))
    assert check_crl(nonum, ca) == 0                                       # sin mínimo exigido se admite
    with pytest.raises(CrlRejected, match="no lleva número"):
        check_crl(nonum, ca, min_number=1)


def test_check_crl_refuses_a_list_from_another_authority(lab, tmp_path_factory):
    d, ca, ck, cc = lab
    d2 = tmp_path_factory.mktemp("otra")
    _ca2, ck2, cc2 = pki.issue_ca(d2, cn="Otra CA")
    with pytest.raises(CrlRejected, match="ninguna CA de confianza"):
        check_crl(pki.issue_crl(d2, ck2, cc2, []), ca)


def test_check_crl_refuses_a_list_with_the_right_name_but_a_forged_signature(lab, tmp_path_factory):
    d, ca, ck, cc = lab
    d2 = tmp_path_factory.mktemp("falsa")
    _ca2, ck2, _cc2 = pki.issue_ca(d2, cn=cc.subject.rfc4514_string().removeprefix("CN="))   # misma identidad, OTRA clave
    forged = pki.issue_crl(d2, ck2, cc, [])                                                    # emisor = la CA real, firmada con otra clave
    with pytest.raises(CrlRejected, match="firma"):
        check_crl(forged, ca)


def test_check_crl_refuses_a_list_that_is_expired_or_from_the_future(lab):
    d, ca, ck, cc = lab
    crl = pki.issue_crl(d, ck, cc, [], days=1)
    now = dt.datetime.now(dt.timezone.utc)
    with pytest.raises(CrlRejected, match="caducada"):
        check_crl(crl, ca, now=now + dt.timedelta(days=2))
    with pytest.raises(CrlRejected, match="futura"):
        check_crl(crl, ca, now=now - dt.timedelta(days=1))


def test_check_crl_refuses_missing_or_garbage_files(lab, tmp_path):
    d, ca, ck, cc = lab
    good = pki.issue_crl(d, ck, cc, [])
    with pytest.raises(CrlRejected, match="no se puede leer"):
        check_crl(tmp_path / "no-existe.pem", ca)
    junk = tmp_path / "junk.pem"
    junk.write_text("no es una CRL")
    with pytest.raises(CrlRejected, match="no se puede leer"):
        check_crl(junk, ca)
    with pytest.raises(CrlRejected, match="CA"):
        check_crl(good, junk)
    with pytest.raises(CrlRejected, match="CA"):
        check_crl(good, tmp_path / "no-existe.pem")


def test_crl_rejected_is_a_qce_error():
    from qce.core.errors import QCEError
    assert issubclass(CrlRejected, QCEError) and crlmod.CrlRejected is CrlRejected


def test_every_issued_crl_carries_an_increasing_number(lab):
    d, ca, ck, cc = lab
    n = x509.load_pem_x509_crl(pki.issue_crl(d, ck, cc, [], number=12).read_bytes()).extensions.get_extension_for_class(x509.CRLNumber).value.crl_number
    assert n == 12
    assert x509.load_pem_x509_crl(pki.issue_crl(d, ck, cc, []).read_bytes()).extensions.get_extension_for_class(x509.CRLNumber).value.crl_number == 1


# --- 3. KME emulado -------------------------------------------------------------------------------------------------------------------------------------



def test_a_silent_client_cannot_block_the_kme_for_everybody_else(env):
    mute = socket.create_connection(("127.0.0.1", env.kme.port))        # conecta y no dice nada (antes: el apretón TLS bloqueaba el hilo de aceptación)
    try:
        t0 = time.monotonic()
        status, body = env.transport("sae-master").request("GET", "/api/v1/keys/sae-slave/status")
        assert status == 200 and json.loads(body)["stored_key_count"] == 0
        assert time.monotonic() - t0 < 3
    finally:
        mute.close()


def _raw_https(env, headers: str, sae="sae-master"):
    cert, key = env.certs[sae]
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(str(env.ca))
    ctx.load_cert_chain(str(cert), str(key))
    raw = socket.create_connection(("127.0.0.1", env.kme.port), timeout=5)
    s = ctx.wrap_socket(raw, server_hostname="kme.lab")
    s.sendall((f"POST /api/v1/keys/sae-slave/enc_keys HTTP/1.1\r\nHost: kme.lab\r\n{headers}\r\n").encode())
    chunks = []
    while chunk := s.recv(4096):                                          # HTTP/1.0: el servidor cierra al terminar
        chunks.append(chunk)
    s.close()
    data = b"".join(chunks).decode("utf-8")
    head, _, body = data.partition("\r\n\r\n")
    return int(head.split()[1]), json.loads(body)["message"]


@pytest.mark.parametrize("headers,status,message", [("Content-Length: 99999999\r\n", 413, "demasiado grande"), ("Content-Length: -5\r\n", 400, "Content-Length inválido"),
                                                    ("Content-Length: abc\r\n", 400, "Content-Length inválido")])
def test_hostile_content_length_is_refused_before_reading_the_body(env, headers, status, message):
    got, data = _raw_https(env, headers)
    assert got == status and message in data                               # el mensaje distingue «rechazado por la cabecera» de «el cuerpo no era JSON»


def test_the_kme_caps_simultaneous_connections(env):
    from qce.qkd.etsi014_emulator import EmulatedKME
    from tests.test_etsi014 import MASTER, SLAVE, client_ctx, server_ctx
    from qce.qkd.etsi014 import HttpsTransport
    kme = EmulatedKME(server_ctx(env.scert, env.skey, env.ca), MASTER, SLAVE, max_connections=1).start()
    holders = []
    try:
        holders.append(socket.create_connection(("127.0.0.1", kme.port)))     # ocupa el único hueco (no completa el apretón)
        time.sleep(0.3)
        extra = socket.create_connection(("127.0.0.1", kme.port))
        extra.settimeout(3)
        assert extra.recv(1) == b""                                           # cerrada al instante
        extra.close()
        assert kme.rejected_busy == 1
        holders.pop().close()                                                 # al colgar el que ocupaba el hueco, el hilo termina y lo devuelve
        time.sleep(0.5)
        cert, key = env.certs[MASTER]
        ok = HttpsTransport("127.0.0.1", kme.port, client_ctx(env.ca, cert, key), timeout=5.0, pin_required=False)
        assert ok.request("GET", f"/api/v1/keys/{SLAVE}/status")[0] == 200   # y otra conexión ya entra
    finally:
        for h in holders:
            h.close()
        kme.close()


# --- 4. servidor PSK -------------------------------------------------------------------------------------------------------------------------------------

from tests.test_tls13_psk import HAVE_LIB, KEY, KID, client, echo  # noqa: E402
from qce.qkd.sources import OneTimeKeys  # noqa: E402
from qce.transport import tls13_psk as P  # noqa: E402

needs_psk = pytest.mark.skipif(not HAVE_LIB, reason="sin OpenSSL ≥ 3.5 utilizable")


@needs_psk
def test_the_psk_server_caps_simultaneous_connections_and_gives_the_slot_back():
    import threading
    gate = threading.Event()
    store = OneTimeKeys({KID: KEY, b"kid-2": KEY, b"kid-3": KEY})
    srv = P.PskServer(store, lambda c: gate.wait(10), timeout=5.0, max_connections=1).start()
    try:
        first = client(srv)                                                   # ocupa el único hueco: su manejador espera
        time.sleep(0.3)
        extra = socket.create_connection(("127.0.0.1", srv.port))
        extra.settimeout(3)
        assert extra.recv(1) == b""                                           # sin hueco: cerrada al instante, sin hilo ni apretón
        extra.close()
        assert srv.rejected_busy == 1
        gate.set()
        first.close()
        time.sleep(0.5)
        assert client(srv, b"kid-2") is not None                              # el hueco vuelve cuando termina el manejador
    finally:
        gate.set()
        srv.close()


@needs_psk
def test_a_transient_accept_error_does_not_kill_the_psk_server():
    import errno
    store = OneTimeKeys({KID: KEY})
    srv = P.PskServer(store, echo, timeout=5.0)

    class Flaky:
        def __init__(self, real):
            self.real, self.n = real, 0

        def accept(self):
            if self.n < 2:
                self.n += 1
                raise OSError(errno.EMFILE, "demasiados archivos abiertos")
            return self.real.accept()

        def __getattr__(self, a):
            return getattr(self.real, a)
    flaky = Flaky(srv._ls)
    srv._ls = flaky
    srv.start()
    try:
        c = client(srv)
        c.send_frame(b"abc")
        assert c.recv_frame() == b"cba"
        assert flaky.n == 2 and srv._thread.is_alive()
        c.close()
    finally:
        srv.close()
    time.sleep(0.3)
    assert not srv._thread.is_alive()


def test_psk_server_limits_must_be_positive():
    with pytest.raises(ValueError):
        P.PskServer(OneTimeKeys({}), echo, max_connections=0)


# --- 5. CLI fuera del clon, marcador STABLE ----------------------------------------------------------------------------------------------------------------

def test_the_cli_refuses_to_run_outside_a_repository_clone(tmp_path, monkeypatch, capsys):
    from qce import cli
    monkeypatch.setattr(cli, "ROOT", tmp_path)                             # p. ej. el directorio que contiene site-packages
    assert cli.main(["status"]) == 2
    err = capsys.readouterr().err
    assert "clon del repositorio" in err and "QCE_ROOT" in err
    assert list(tmp_path.iterdir()) == []                                  # y no escribió nada allí


def test_the_cli_runs_in_a_clone_layout(tmp_path, monkeypatch):
    from qce import cli
    from tests.test_audit_findings import mini_project
    root = mini_project(tmp_path)
    monkeypatch.setattr(cli, "ROOT", root)
    assert cli._is_project_root(root)
    assert not cli._is_project_root(tmp_path / "otro")
    (root / "gates.json").unlink()
    assert not cli._is_project_root(root)                                  # solo uno de los dos no basta
    (root / "gates.json").write_text("{}")
    import shutil
    shutil.rmtree(root / "qce")
    assert not cli._is_project_root(root)


def test_qce_root_points_the_cli_at_a_clone(tmp_path):
    out = subprocess.run([sys.executable, "-c", "import qce.cli as c; print(c.ROOT)"], capture_output=True, text=True, cwd=tmp_path,
                         env={**os.environ, "QCE_ROOT": str(tmp_path), "PYTHONPATH": str(ROOT)})
    assert out.returncode == 0 and out.stdout.strip() == str(tmp_path.resolve())


def test_a_failed_write_of_the_stable_marker_keeps_the_previous_one(tmp_path, monkeypatch):
    from qce.core import atomic
    from qce.pqc.hybrid import HybridSigPrivateKey
    from qce.recovery import release as rel
    from tests.test_audit_findings import mini_project, snap
    (tmp_path / "p").mkdir()
    root = mini_project(tmp_path / "p")
    key = HybridSigPrivateKey.generate()
    m1, _ = snap(root, key, sequence=1)
    rel.mark_stable(root, m1["release_id"], "humano")
    before = (root / "releases" / "STABLE").read_bytes()
    (root / "qce" / "m.py").write_text("def f(x):\n    return True\n")
    m2, _ = snap(root, key, sequence=2)

    def boom(src, dst):
        raise OSError("corte")
    monkeypatch.setattr(atomic.os, "replace", boom)
    with pytest.raises(OSError):
        rel.mark_stable(root, m2["release_id"], "humano")
    monkeypatch.undo()
    assert (root / "releases" / "STABLE").read_bytes() == before            # el marcador anterior sigue entero
    assert not [p for p in (root / "releases").iterdir() if p.name.startswith(".STABLE")]   # sin temporales sobrantes
    rel.mark_stable(root, m2["release_id"], "humano")                       # y la promoción se puede repetir
    assert json.loads((root / "releases" / "STABLE").read_text())["release_id"] == m2["release_id"]


def _anchor_module():
    import importlib.util
    spec = importlib.util.spec_from_file_location("qce_tools_anchor", ROOT / "tools" / "anchor.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.mark.skipif(not (ROOT / "tools" / "anchor.py").exists(), reason="solo en el repositorio completo (el sandbox de mutación no lleva tools/)")
def test_the_external_anchor_covers_the_stable_marker_only_when_it_exists(tmp_path):
    from tests.test_audit_findings import mini_project
    anchor = _anchor_module()
    root = mini_project(tmp_path)
    (root / "learning").mkdir()
    (root / "learning" / "incidents.jsonl").write_text("")
    (root / "trust").mkdir()
    (root / "trust" / "registry.json").write_text("{}")
    without = anchor.build(root, commit="c")
    assert "stable_sha256" not in without                                  # los resúmenes ya atestiguados (sin marcador) no cambian
    (root / "releases").mkdir()
    (root / "releases" / "STABLE").write_text(json.dumps({"release_id": "R1", "approver": "humano"}))
    with_marker = anchor.build(root, commit="c")
    import hashlib
    assert with_marker["stable_sha256"] == hashlib.sha256((root / "releases" / "STABLE").read_bytes()).hexdigest()
    (root / "releases" / "STABLE").write_text(json.dumps({"release_id": "R0", "approver": "humano"}))   # alguien lo mueve a un snapshot viejo
    assert anchor.build(root, commit="c")["stable_sha256"] != with_marker["stable_sha256"]   # el resumen anclado lo delata
    assert {k: v for k, v in with_marker.items() if k != "stable_sha256"} == without
