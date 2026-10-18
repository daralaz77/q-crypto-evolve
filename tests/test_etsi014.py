"""Adaptador ETSI GS QKD 014 contra el EMULADOR de KME (simulación), con TLS mutuo, el broker y el transporte TLS 1.3 con PSK."""
import base64
import hashlib
import json
import ssl
import uuid

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from qce.core.chainlog import ChainLog
from qce.core.errors import PolicyViolation
from qce.core.policy import Policy
from qce.qkd.broker import KeyBroker
from qce.qkd.contract import ErrorCategory, QKDDeviceError
from qce.qkd.devices import DeviceRegistry
from qce.qkd.etsi014 import Etsi014Adapter, HttpsTransport, KEY_ID_RE
from qce.qkd.etsi014_emulator import EmulatedKME
from qce.transport import pki
from qce.transport import tls13_psk as P
from qce.qkd.sources import BrokerSource

MASTER, SLAVE = "sae-master", "sae-slave"
LAB = Policy(allow_simulated_qkd=True)


def server_ctx(cert, key, ca):
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    c.minimum_version = ssl.TLSVersion.TLSv1_3
    c.load_cert_chain(str(cert), str(key))
    c.verify_mode = ssl.CERT_REQUIRED
    c.load_verify_locations(str(ca))
    return c


def client_ctx(ca, cert=None, key=None):
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    c.minimum_version = ssl.TLSVersion.TLSv1_3
    c.load_verify_locations(str(ca))
    if cert:
        c.load_cert_chain(str(cert), str(key))
    return c


@pytest.fixture()
def env(tmp_path):
    ca, ck, cc = pki.issue_ca(tmp_path)
    scert, skey = pki.issue_leaf(tmp_path, ck, cc, "kme.lab", server=True)
    certs = {n: pki.issue_leaf(tmp_path, ck, cc, n, server=False) for n in (MASTER, SLAVE, "intruso")}
    kme = EmulatedKME(server_ctx(scert, skey, ca), MASTER, SLAVE).start()
    fp = hashlib.sha256(ssl.PEM_cert_to_DER_cert(scert.read_text())).digest()

    def transport(sae, timeout=5.0):
        c = certs[sae]
        return HttpsTransport("127.0.0.1", kme.port, client_ctx(ca, c[0], c[1]), timeout=timeout)

    def adapter(role, **kw):
        sae, peer = (MASTER, SLAVE) if role == "master" else (SLAVE, MASTER)
        return Etsi014Adapter(f"kme-{role}", transport(sae), sae, peer, role, is_simulation=True, **kw)

    class E:
        pass
    e = E()
    e.kme, e.fp, e.transport, e.adapter, e.ca, e.certs, e.tmp, e.scert, e.skey, e.ck, e.cc = kme, fp, transport, adapter, ca, certs, tmp_path, scert, skey, ck, cc
    yield e
    kme.close()


def brokers(env, spec=(("trusted_hops", 0),), fp=None, policy=LAB):
    out = {}
    for role in ("master", "slave"):
        audit = ChainLog(env.tmp / f"audit-{role}.jsonl")
        reg = DeviceRegistry(audit)
        ad = env.adapter(role)
        reg.enroll(ad.device_id, "ETSI-014", "KME", "n/a", fp or env.fp, approved_by="darwin", protocol="ETSI-014-KME", spec=spec)
        ad.initialize({"registry": reg})
        b = KeyBroker(policy, reg, audit, allowed_consumers={"L1": {"sess"}})
        out[role] = (b, ad, reg)
    return out


# ---- extremo a extremo -----------------------------------------------------------------------------------------------
def test_master_and_slave_get_the_same_key_through_the_brokers_and_it_is_delivered_once(env):
    bs = brokers(env)
    for b, ad, reg in bs.values():
        b.attach("L1", ad)
    bm, bsl = bs["master"][0], bs["slave"][0]
    [kid] = bm.refill("L1", 1)
    assert KEY_ID_RE.match(kid)
    ref, secret = bm.take("L1", "sess")
    assert ref.decode() == kid if isinstance(ref, bytes) else ref == kid
    ref2, secret2 = bsl.take("L1", "sess", kid)                  # la esclava pide por key_ID (dec_keys)
    assert secret == secret2 and len(secret) == 32
    with pytest.raises(QKDDeviceError):
        bsl.take("L1", "sess", kid)                              # el KME entrega cada key_ID una sola vez
    assert env.kme.stored == 0


def test_qkd_key_from_the_etsi_emulator_feeds_tls13_with_external_psk_end_to_end(env):
    try:
        P._load()
    except P.PskTransportUnavailable:
        pytest.skip("sin OpenSSL ≥ 3.5")
    bs = brokers(env)
    for b, ad, reg in bs.values():
        b.attach("L1", ad)
    bm, bsl = bs["master"][0], bs["slave"][0]
    bm.refill("L1", 1)
    kid, key = bm.take("L1", "sess")
    kid = kid if isinstance(kid, bytes) else kid.encode()
    srv = P.PskServer(BrokerSource(bsl, "L1", "sess"), lambda c: c.send_frame(c.recv_frame()[::-1])).start()
    c = P.connect_tcp("127.0.0.1", srv.port, kid, key, timeout=5)
    c.send_frame(b"qkd 014")
    assert c.recv_frame() == b"410 dkq"
    assert (c.version, c.group) == ("TLSv1.3", "X25519MLKEM768")
    c.close()
    srv.close()


def test_the_kme_emulator_is_declared_as_simulation_and_production_policy_rejects_it(env):
    b, ad, reg = brokers(env, policy=Policy())["master"]
    assert ad.get_capabilities().is_simulation is True
    with pytest.raises(PolicyViolation):
        b.attach("L1", ad)


def test_adapter_declares_what_it_is(env):
    caps = env.adapter("master").get_capabilities()
    assert (caps.qkd_protocol, caps.interface_version, caps.authentication_method) == ("ETSI-014-KME", "ETSI GS QKD 014 V1.1.1", "mutual-TLS+certificate-pin")
    assert {"acquire_key", "get_key_service_status", "authenticate_device"} <= caps.supported_operations
    assert "request_key_metadata" not in caps.supported_operations


# ---- identidad y política -----------------------------------------------------------------------------------------------
def test_kme_identity_is_the_pinned_certificate_and_a_different_one_is_untrusted(env):
    b, ad, reg = brokers(env, fp=hashlib.sha256(b"otro certificado").digest())["master"]
    with pytest.raises(QKDDeviceError) as e:
        b.attach("L1", ad)
    assert e.value.category is ErrorCategory.DEVICE_UNTRUSTED
    assert reg.get(ad.device_id).trust_state == "UNTRUSTED"
    with pytest.raises(QKDDeviceError):                          # y no se recupera solo
        ad.authenticate_device()


def test_policy_needs_the_approved_trusted_hops_and_limits_them(env):
    b, ad, reg = brokers(env, spec=())["master"]                 # sin ficha: no se inventa el dato
    b.attach("L1", ad)
    with pytest.raises(PolicyViolation):
        b.refill("L1", 1)
    b2, ad2, _ = brokers(env, spec=(("trusted_hops", 3),))["master"]
    b2.attach("L1", ad2)
    with pytest.raises(PolicyViolation):
        b2.refill("L1", 1)                                       # 3 saltos > máximo de la política (0)
    b3, ad3, _ = brokers(env, policy=Policy(allow_simulated_qkd=True, min_assurance=2))["master"]
    with pytest.raises(PolicyViolation):
        b3.attach("L1", ad3)                                     # garantía mínima E91: un KME de confianza no la alcanza


def test_unauthorized_sae_and_missing_client_certificate_are_rejected(env):
    bad = Etsi014Adapter("x", env.transport("intruso"), MASTER, SLAVE, "master", is_simulation=True)
    with pytest.raises(QKDDeviceError) as e:
        bad.get_health_status()
    assert e.value.category is ErrorCategory.AUTHENTICATION_FAILURE
    nocert = Etsi014Adapter("y", HttpsTransport("127.0.0.1", env.kme.port, client_ctx(env.ca), timeout=3), MASTER, SLAVE, "master", is_simulation=True)
    with pytest.raises(QKDDeviceError) as e:
        nocert.get_health_status()
    assert e.value.category in (ErrorCategory.AUTHENTICATION_FAILURE, ErrorCategory.CONNECTION_FAILURE)


def test_connection_failures_and_timeouts_map_to_their_categories(env):
    ad = env.adapter("master")
    env.kme.close()
    with pytest.raises(QKDDeviceError) as e:
        ad.get_health_status()
    assert e.value.category is ErrorCategory.CONNECTION_FAILURE


# ---- validación de respuestas (transporte falso) --------------------------------------------------------------------------
class Fake:
    def __init__(self, status=200, body=None, raw=None):
        self.status, self.body, self.raw, self.calls = status, body, raw, []

    def request(self, method, path, body=None):
        self.calls.append((method, path, body))
        return self.status, self.raw if self.raw is not None else json.dumps(self.body).encode()

    def peer_certificate_der(self):
        return b"der"


def uid():
    return str(uuid.uuid4())


def key_b64(n=32, fill=7):
    return base64.b64encode(bytes([fill]) * n).decode()


def adapter(fake, role="master", bits=256):
    return Etsi014Adapter("d", fake, "a", "b", role, key_size_bits=bits, is_simulation=True)


STATUS = {"key_size": 256, "stored_key_count": 3, "max_key_count": 10, "max_key_per_request": 2, "max_key_size": 512, "min_key_size": 64}


def test_http_errors_map_to_categories_and_never_echo_a_key():
    for status, cat in ((400, ErrorCategory.PROTOCOL_MISMATCH), (401, ErrorCategory.AUTHENTICATION_FAILURE), (503, ErrorCategory.KEY_EXHAUSTION), (500, ErrorCategory.UNKNOWN_ERROR), (404, ErrorCategory.UNKNOWN_ERROR)):
        with pytest.raises(QKDDeviceError) as e:
            adapter(Fake(status, {"message": "x" * 200})).get_health_status()
        assert e.value.category is cat and len(str(e.value)) < 140        # el mensaje remoto se trunca
    for raw in (b"no json", b"[]", b"3", b"null"):
        with pytest.raises(QKDDeviceError) as e:
            adapter(Fake(200, raw=raw)).get_health_status()
        assert e.value.category is ErrorCategory.INVALID_RESPONSE


def test_status_requires_every_field_as_a_non_negative_integer():
    assert adapter(Fake(200, STATUS)).get_health_status()["stored_key_count"] == 3
    assert adapter(Fake(200, STATUS)).get_key_service_status() == {"available_keys": 3, "qber": None, "witnesses": {"key_size_bits": 256}}
    for k in STATUS:
        for bad in (None, "3", -1, True, 1.5):
            st = dict(STATUS)
            st[k] = bad
            with pytest.raises(QKDDeviceError):
                adapter(Fake(200, st)).get_health_status()
        st = dict(STATUS)
        del st[k]
        with pytest.raises(QKDDeviceError):
            adapter(Fake(200, st)).get_health_status()


def test_master_key_response_is_validated_strictly():
    ok = {"keys": [{"key_ID": uid(), "key": key_b64()}]}
    ref, mat = adapter(Fake(200, ok)).acquire_key({"link_id": "L1"})
    assert ref.peer_or_link_id == "L1" and ref.is_simulation and len(mat.reveal()) == 32 and "07" not in repr(mat)
    for bad in ({"keys": []}, {"keys": [ok["keys"][0], ok["keys"][0]]}, {"keys": "x"}, {}, {"keys": [{"key_ID": "no-uuid", "key": key_b64()}]},
                {"keys": [{"key_ID": uid(), "key": "!!!no base64!!!"}]}, {"keys": [{"key_ID": uid(), "key": key_b64(31)}]},
                {"keys": [{"key_ID": uid(), "key": key_b64(33)}]}, {"keys": [{"key_ID": uid()}]}, {"keys": [{"key": key_b64()}]}, {"keys": [5]},
                {"keys": [{"key_ID": uid(), "key": 12}]}, {"keys": [{"key_ID": uid(), "key": key_b64()[:20] + "!" + key_b64()[20:]}]}):
        with pytest.raises(QKDDeviceError) as e:
            adapter(Fake(200, bad)).acquire_key({"link_id": "L1"})
        assert key_b64() not in str(e.value) and e.value.category in (ErrorCategory.INVALID_RESPONSE, ErrorCategory.INTEGRITY_FAILURE)


def test_slave_asks_by_key_id_and_only_accepts_that_key():
    want = uid()
    f = Fake(200, {"keys": [{"key_ID": want, "key": key_b64()}]})
    ref, _ = adapter(f, "slave").acquire_key({"link_id": "L1", "key_id": want})
    assert ref.key_reference == want and f.calls[0][:2] == ("POST", "/api/v1/keys/b/dec_keys") and f.calls[0][2] == {"key_IDs": [{"key_ID": want}]}
    with pytest.raises(QKDDeviceError) as e:
        adapter(Fake(200, {"keys": [{"key_ID": uid(), "key": key_b64()}]}), "slave").acquire_key({"link_id": "L1", "key_id": want})
    assert e.value.category is ErrorCategory.INTEGRITY_FAILURE
    for bad in (None, "", "no-uuid", 5):
        with pytest.raises(QKDDeviceError) as e:
            adapter(Fake(200, {"keys": []}), "slave").acquire_key({"link_id": "L1", "key_id": bad})
        assert e.value.category is ErrorCategory.PROTOCOL_MISMATCH


def test_master_requests_exactly_one_key_of_the_configured_size():
    f = Fake(200, {"keys": [{"key_ID": uid(), "key": key_b64(48)}]})
    adapter(f, bits=384).acquire_key({"link_id": "L"})
    assert f.calls[0] == ("POST", "/api/v1/keys/b/enc_keys", {"number": 1, "size": 384})


def test_constructor_validates_role_sae_ids_and_key_size_at_the_limits():
    mk = lambda **k: Etsi014Adapter("d", Fake(), **({"own_sae_id": "a", "peer_sae_id": "b", "role": "master"} | k))      # noqa: E731
    for bad in ({"role": "otro"}, {"own_sae_id": ""}, {"peer_sae_id": "con espacio"}, {"own_sae_id": "x" * 129}, {"key_size_bits": 127}, {"key_size_bits": 4097},
                {"key_size_bits": 130}):
        with pytest.raises(PolicyViolation):
            mk(**bad)
    mk(key_size_bits=128)
    mk(key_size_bits=4096)
    mk(own_sae_id="x" * 128)


def test_authentication_needs_initialization_and_report_consumption_is_a_declared_noop():
    ad = adapter(Fake(200, STATUS))
    with pytest.raises(QKDDeviceError) as e:
        ad.authenticate_device()
    assert e.value.category is ErrorCategory.DEVICE_UNTRUSTED
    assert ad.report_key_consumption("x") is None and ad.shutdown() is None
    assert ad.peer_certificate_fingerprint() == hashlib.sha256(b"der").digest()


def test_a_silent_server_times_out_and_an_unknown_ca_is_an_authentication_failure(env):
    import socket
    ls = socket.socket()
    ls.bind(("127.0.0.1", 0))
    ls.listen(8)
    silent = HttpsTransport("127.0.0.1", ls.getsockname()[1], client_ctx(env.ca, *env.certs[MASTER]), timeout=0.5)
    for call in (lambda: silent.request("GET", "/x"), silent.peer_certificate_der):
        with pytest.raises(QKDDeviceError) as e:
            call()
        assert e.value.category is ErrorCategory.SERVICE_UNAVAILABLE
    ls.close()
    other_ca, _, _ = pki.issue_ca(env.tmp / "otra") if (env.tmp / "otra").mkdir() is None else None
    wrong = HttpsTransport("127.0.0.1", env.kme.port, client_ctx(other_ca, *env.certs[MASTER]), timeout=3)
    for call in (lambda: wrong.request("GET", "/x"), wrong.peer_certificate_der):
        with pytest.raises(QKDDeviceError) as e:
            call()
        assert e.value.category is ErrorCategory.AUTHENTICATION_FAILURE


def test_peer_certificate_is_the_pinned_one_and_a_refused_connection_is_reported(env):
    tr = env.transport(MASTER)
    assert hashlib.sha256(tr.peer_certificate_der()).digest() == env.fp
    env.kme.close()
    with pytest.raises(QKDDeviceError) as e:
        tr.peer_certificate_der()
    assert e.value.category is ErrorCategory.CONNECTION_FAILURE


def test_a_device_marked_untrusted_stays_untrusted_until_a_named_person_approves_it(env):
    b, ad, reg = brokers(env)["master"]
    reg.set_untrusted(ad.device_id, "sospecha")
    with pytest.raises(QKDDeviceError) as e:
        b.attach("L1", ad)
    assert e.value.category is ErrorCategory.DEVICE_UNTRUSTED and "aprobación humana" in str(e.value)
    reg.approve(ad.device_id, "darwin")
    b.attach("L1", ad)                                           # con la aprobación vuelve a poder autenticarse
    assert reg.is_trusted(ad.device_id)


def test_oversized_responses_are_rejected(env, monkeypatch):
    import qce.qkd.etsi014 as E
    monkeypatch.setattr(E, "MAX_RESPONSE", 10)
    with pytest.raises(QKDDeviceError) as e:
        env.adapter("master").get_health_status()
    assert e.value.category is ErrorCategory.INVALID_RESPONSE


def test_duplicate_or_unrequested_ids_are_rejected_when_several_keys_are_asked():
    a, b = uid(), uid()
    ad = adapter(Fake(), bits=256)
    good = {"keys": [{"key_ID": a, "key": key_b64()}, {"key_ID": b, "key": key_b64()}]}
    assert [k for k, _ in ad._parse_keys(good, None, 2)] == [a, b]
    assert [k for k, _ in ad._parse_keys(good, [a, b], 2)] == [a, b]
    dup = {"keys": [{"key_ID": a, "key": key_b64()}, {"key_ID": a, "key": key_b64()}]}
    with pytest.raises(QKDDeviceError) as e:
        ad._parse_keys(dup, None, 2)
    assert e.value.category is ErrorCategory.INTEGRITY_FAILURE
    with pytest.raises(QKDDeviceError) as e:
        ad._parse_keys(good, [a], 2)                             # b no se pidió
    assert e.value.category is ErrorCategory.INTEGRITY_FAILURE


def test_oversized_response_is_reported_as_too_big_and_a_peer_without_certificate_is_untrusted(env, monkeypatch):
    import qce.qkd.etsi014 as E
    monkeypatch.setattr(E, "MAX_RESPONSE", 10)
    with pytest.raises(QKDDeviceError) as e:
        env.adapter("master").get_health_status()
    assert "demasiado grande" in str(e.value)
    monkeypatch.undo()

    class Sock:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def getpeercert(self, binary_form=False):
            return None

    class Ctx:
        def wrap_socket(self, raw, server_hostname=None):
            raw.close()
            return Sock()
    tr = HttpsTransport("127.0.0.1", env.kme.port, Ctx(), timeout=3)
    with pytest.raises(QKDDeviceError) as e:
        tr.peer_certificate_der()
    assert e.value.category is ErrorCategory.DEVICE_UNTRUSTED
