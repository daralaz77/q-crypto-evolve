import json

import pytest

from qce.core.chainlog import ChainLog
from qce.core.errors import PolicyViolation, QKDAnomaly
from qce.core.policy import Policy
from qce.pqc.hybrid import HybridSigPrivateKey
from qce.protocols.session import ClientHandshake, ServerHandshake
from qce.qkd.broker import KeyBroker
from qce.qkd.contract import (DeviceAdapter, DeviceEvent, ErrorCategory, KeyMaterial, KeyState, QKDDeviceError)
from qce.qkd.devices import DeviceRegistry, SimulatedAdapter, SimulatedLink

LAB = Policy(allow_simulated_qkd=True)


class Clock:
    t = 1000.0

    def __call__(self):
        return self.t


def build(tmp_path, policy=LAB, faults=(), clock=None, consumers=("sess",)):
    clock = clock or Clock()
    audit = ChainLog(tmp_path / "qkd-audit.jsonl", clock)
    reg = DeviceRegistry(audit, clock)
    link = SimulatedLink("L1")
    dev = SimulatedAdapter("devA", link, clock=clock)
    reg.enroll("devA", "SIMULATION", "sim", dev.firmware, dev.identity.public_bytes, approved_by="darwin")
    dev.initialize({"registry": reg})
    dev.faults |= set(faults)
    broker = KeyBroker(policy, reg, audit, clock, {"L1": set(consumers)})
    return broker, dev, link, reg, clock, audit


def attach(broker, dev):
    broker.attach("L1", dev)


# ---- contrato -------------------------------------------------------------------------------------
def test_unimplemented_operations_are_declared_unsupported():
    class Bare(DeviceAdapter):
        pass
    with pytest.raises(QKDDeviceError) as e:
        Bare().acquire_key({})
    assert e.value.category is ErrorCategory.PROTOCOL_MISMATCH and "no soportada" in str(e.value)


def test_simulator_declares_itself_as_simulation(tmp_path):
    _, dev, *_ = build(tmp_path)
    caps = dev.get_capabilities()
    assert caps.is_simulation and caps.manufacturer == "SIMULATION"


# ---- identidad y registro ----------------------------------------------------------------------------
def test_enrollment_requires_named_human_and_no_silent_retrust(tmp_path):
    reg = DeviceRegistry()
    with pytest.raises(PolicyViolation):
        reg.enroll("d", "m", "x", "1", b"k", approved_by="  ")
    reg.enroll("d", "m", "x", "1", b"k", approved_by="darwin")
    with pytest.raises(PolicyViolation):
        reg.enroll("d", "m", "x", "1", b"k2", approved_by="darwin")


def test_unknown_device_cannot_authenticate(tmp_path):
    broker, dev, link, reg, *_ = build(tmp_path)
    ghost = SimulatedAdapter("ghost", link)
    ghost.initialize({"registry": reg})
    with pytest.raises(QKDDeviceError) as e:
        broker.attach("L1", ghost)
    assert e.value.category is ErrorCategory.DEVICE_UNTRUSTED


def test_impersonator_with_other_identity_key_is_untrusted(tmp_path):
    broker, dev, *_ = build(tmp_path, faults=("bad_identity",))
    with pytest.raises(QKDDeviceError) as e:
        attach(broker, dev)
    assert e.value.category is ErrorCategory.DEVICE_UNTRUSTED
    assert not broker.registry.is_trusted("devA")


def test_recorded_auth_response_cannot_be_replayed(tmp_path):
    broker, dev, link, reg, *_ = build(tmp_path)
    recorded = {}
    orig = dev.challenge_response

    def spy(nonce):
        recorded["r"] = orig(nonce)
        return recorded["r"]
    dev.challenge_response = spy
    reg.authenticate(dev)  # sesión legítima: se captura la respuesta
    dev.challenge_response = lambda nonce: recorded["r"]  # el atacante repite la captura
    with pytest.raises(QKDDeviceError) as e:
        reg.authenticate(dev)
    assert e.value.category is ErrorCategory.AUTHENTICATION_FAILURE


def test_firmware_change_removes_trust_until_reviewed(tmp_path):
    broker, dev, link, reg, *_ = build(tmp_path)
    attach(broker, dev)
    link.generate(2)
    broker.refill("L1")
    dev.handle_device_event(DeviceEvent("firmware_changed", {"version": "SIM-9.9"}))
    assert reg.get("devA").trust_state == "REVIEW_REQUIRED"
    with pytest.raises(QKDDeviceError) as e:
        broker.refill("L1")
    assert e.value.category is ErrorCategory.DEVICE_UNTRUSTED
    with pytest.raises(QKDDeviceError):
        broker.reserve("L1", "sess")  # tampoco se reservan claves de un dispositivo sin confianza


# ---- política: simulación y fail-closed ----------------------------------------------------------------------
def test_simulated_device_rejected_under_production_policy(tmp_path):
    broker, dev, *_ = build(tmp_path, policy=Policy())
    with pytest.raises(PolicyViolation):
        attach(broker, dev)


def test_fail_closed_no_silent_fallback_on_any_device_fault(tmp_path):
    expected = {"connection_loss": ErrorCategory.CONNECTION_FAILURE, "latency": ErrorCategory.SERVICE_UNAVAILABLE,
                "health_fail": ErrorCategory.DEVICE_HEALTH_FAILURE}
    for fault, cat in expected.items():
        broker, dev, link, *_ = build(tmp_path / fault)
        attach(broker, dev)
        dev.faults.add(fault)
        link.generate(1)
        with pytest.raises(QKDDeviceError) as e:
            broker.refill("L1")
        assert e.value.category is cat
        assert broker.status("L1")["keys"] == {}  # nada se entrega; no hay "modo clásico" implícito


def test_key_exhaustion_and_malformed_response(tmp_path):
    broker, dev, link, *_ = build(tmp_path)
    attach(broker, dev)
    with pytest.raises(QKDDeviceError) as e:
        broker.refill("L1")
    assert e.value.category is ErrorCategory.KEY_EXHAUSTION
    link.generate(1)
    dev.faults.add("malformed")
    with pytest.raises(QKDDeviceError) as e:
        broker.refill("L1")
    assert e.value.category is ErrorCategory.INVALID_RESPONSE


def test_restart_mid_operation_never_leaves_a_reusable_key(tmp_path):
    broker, dev, link, *_ = build(tmp_path)
    attach(broker, dev)
    [kid] = link.generate(1)
    dev.faults.add("restart_mid_op")
    with pytest.raises(QKDDeviceError):
        broker.refill("L1")
    dev.faults.clear()
    with pytest.raises(QKDDeviceError) as e:
        broker.refill("L1", key_id=kid)  # el dispositivo ya entregó ese key_ID: estado incierto → no se reutiliza
    assert e.value.category is ErrorCategory.KEY_EXHAUSTION


def test_eavesdropper_quarantines_link_and_blocks_everything_after(tmp_path):
    broker, dev, link, *_ = build(tmp_path)
    attach(broker, dev)
    link.generate(2)
    dev.faults.add("eavesdropper")
    with pytest.raises(QKDAnomaly):
        broker.refill("L1")
    dev.faults.clear()  # aunque el síntoma desaparezca, no se rehabilita solo
    with pytest.raises(QKDAnomaly):
        broker.refill("L1")
    with pytest.raises(QKDAnomaly):
        broker.reserve("L1", "sess")


def test_tampered_key_goes_to_quarantine_and_material_is_destroyed(tmp_path):
    broker, dev, link, *_ = build(tmp_path, faults=("tamper",))
    attach(broker, dev)
    [kid] = link.generate(1)
    with pytest.raises(QKDDeviceError) as e:
        broker.refill("L1")
    assert e.value.category is ErrorCategory.INTEGRITY_FAILURE
    assert broker.metadata(kid).state is KeyState.QUARANTINED
    assert kid not in broker._mat


# ---- ciclo de vida de claves ---------------------------------------------------------------------------------
def ready(tmp_path, n=1, **kw):
    broker, dev, link, reg, clock, audit = build(tmp_path, **kw)
    attach(broker, dev)
    ids = link.generate(n)
    got = broker.refill("L1", n)
    return broker, dev, link, reg, clock, audit, got


def test_reserve_consume_once_and_never_again(tmp_path):
    broker, *_, got = ready(tmp_path)
    ref = broker.reserve("L1", "sess")
    secret = broker.consume(ref, "sess")
    assert len(secret) == 32 and broker.metadata(ref).state is KeyState.CONSUMED
    with pytest.raises(QKDDeviceError):
        broker.consume(ref, "sess")  # consumo repetido
    with pytest.raises(QKDDeviceError):
        broker.reserve("L1", "sess")  # no queda material


def test_other_consumer_cannot_take_reserved_key_and_unauthorized_is_denied(tmp_path):
    broker, *_ = ready(tmp_path, consumers=("sess", "other"))
    ref = broker.reserve("L1", "sess")
    with pytest.raises(QKDDeviceError):
        broker.consume(ref, "other")
    with pytest.raises(PolicyViolation):
        broker.reserve("L1", "intruso")
    with pytest.raises(PolicyViolation):
        broker.take("L1", "intruso")


def test_expired_key_is_unusable_and_destroyed(tmp_path):
    broker, dev, link, reg, clock, audit, got = ready(tmp_path)
    ref = broker.reserve("L1", "sess")
    clock.t += dev.key_ttl_s + 1
    with pytest.raises(QKDDeviceError) as e:
        broker.consume(ref, "sess")
    assert e.value.category is ErrorCategory.KEY_EXPIRED and broker.metadata(ref).state is KeyState.EXPIRED
    assert ref not in broker._mat


def test_revoked_key_cannot_be_reserved_or_consumed(tmp_path):
    broker, *_, got = ready(tmp_path)
    broker.revoke(got[0], "sospecha")
    with pytest.raises(QKDDeviceError):
        broker.reserve("L1", "sess")
    with pytest.raises(QKDDeviceError):
        broker.consume(got[0], "sess")


def test_duplicate_key_id_from_device_is_rejected(tmp_path):
    broker, dev, link, *_ = build(tmp_path)
    attach(broker, dev)
    [kid] = link.generate(1)
    broker.refill("L1")
    dev._consumed.clear()  # dispositivo defectuoso/comprometido reentrega el mismo key_ID
    with pytest.raises(QKDDeviceError) as e:
        broker.refill("L1", key_id=kid)
    assert e.value.category is ErrorCategory.INTEGRITY_FAILURE


# ---- secretos ---------------------------------------------------------------------------------------------------
def test_secret_never_in_audit_metadata_repr_or_errors(tmp_path):
    broker, dev, link, reg, clock, audit, got = ready(tmp_path)
    secret_hex = dev._pool[got[0]][0].hex()
    ref = broker.reserve("L1", "sess")
    secret = broker.consume(ref, "sess")
    assert secret.hex() == secret_hex
    assert secret_hex not in (tmp_path / "qkd-audit.jsonl").read_text()
    assert secret_hex not in repr(broker.metadata(ref)) and secret_hex not in json.dumps(broker.metadata(ref).__dict__, default=str)
    km = KeyMaterial(secret)
    assert secret_hex not in repr(km) and secret_hex not in str(km)
    with pytest.raises(TypeError):
        import pickle
        pickle.dumps(km)
    km.destroy()
    with pytest.raises(QKDDeviceError) as e:
        km.reveal()
    assert secret_hex not in str(e.value)


# ---- interoperabilidad: QKD + handshake poscuántico ------------------------------------------------------------------
def test_end_to_end_hybrid_session_with_qkd_on_both_ends(tmp_path):
    clock = Clock()
    link = SimulatedLink("L1")
    reg = DeviceRegistry(None, clock)
    brokers, devs = [], []
    for name in ("devA", "devB"):
        d = SimulatedAdapter(name, link, clock=clock)
        reg.enroll(name, "SIMULATION", "sim", d.firmware, d.identity.public_bytes, "darwin")
        d.initialize({"registry": reg})
        b = KeyBroker(LAB, reg, None, clock, {"L1": {"sess"}})
        b.attach("L1", d)
        brokers.append(b)
        devs.append(d)
    link.generate(1)
    brokers[0].refill("L1")
    kid, key = brokers[0].take("L1", "sess")  # iniciador
    ident = HybridSigPrivateKey.generate()
    server = ServerHandshake(ident, LAB, qkd_lookup=lambda qid: brokers[1].take("L1", "sess", qid.decode())[1])
    client = ClientHandshake(ident.public_bytes, LAB, qkd=(kid, key))
    m3 = client.on_server_hello(server.on_client_hello(client.start()))
    m4, ss = server.on_client_finish(m3)
    cs = client.on_server_finish(m4)
    assert ss.open(cs.seal(b"PQC + QKD")) == b"PQC + QKD"
    with pytest.raises(QKDDeviceError):  # la clave QKD ya fue consumida en ambos extremos
        brokers[1].take("L1", "sess", kid.decode())


def test_end_to_end_fails_closed_when_responder_has_no_key(tmp_path):
    clock = Clock()
    link = SimulatedLink("L1")
    reg = DeviceRegistry(None, clock)
    d = SimulatedAdapter("devB", link, clock=clock)
    reg.enroll("devB", "SIMULATION", "sim", d.firmware, d.identity.public_bytes, "darwin")
    d.initialize({"registry": reg})
    b = KeyBroker(LAB, reg, None, clock, {"L1": {"sess"}})
    b.attach("L1", d)
    ident = HybridSigPrivateKey.generate()
    server = ServerHandshake(ident, LAB, qkd_lookup=lambda qid: b.take("L1", "sess", qid.decode())[1])
    client = ClientHandshake(ident.public_bytes, LAB, qkd=(b"deadbeefdeadbeef", b"q" * 32))
    with pytest.raises(QKDDeviceError):  # sin clave en el extremo remoto: no hay sesión degradada
        server.on_client_hello(client.start())


@pytest.mark.parametrize("bad", [float("nan"), -0.1, 0.9, "0.02", None])
def test_broker_rejects_impossible_qber_values_from_the_device(tmp_path, bad):
    broker, dev, link, *_ = build(tmp_path)
    attach(broker, dev)
    link.generate(1)
    good = dev.get_key_service_status
    # solo el QBER es defectuoso: los demás testigos son válidos, así que el rechazo SOLO puede venir de la validación de QBER
    dev.get_key_service_status = lambda key_id=None: {**good(key_id), "qber": bad, "witnesses": {**good(key_id)["witnesses"], "qber": bad}}
    with pytest.raises(QKDDeviceError) as e:
        broker.refill("L1")
    assert e.value.category is ErrorCategory.INVALID_RESPONSE


def test_inconsistent_qber_between_status_and_witnesses_is_rejected(tmp_path):
    broker, dev, link, *_ = build(tmp_path)
    attach(broker, dev)
    link.generate(1)
    good = dev.get_key_service_status
    dev.get_key_service_status = lambda key_id=None: {**good(key_id), "qber": 0.02, "witnesses": {**good(key_id)["witnesses"], "qber": 0.01}}
    with pytest.raises(QKDDeviceError) as e:
        broker.refill("L1")
    assert e.value.category is ErrorCategory.INVALID_RESPONSE and "no coinciden" in str(e.value)


def test_hold_gives_material_without_consuming_and_release_returns_the_key_only_to_its_owner(tmp_path):
    broker, *_, got = ready(tmp_path, consumers=("sess", "other"))
    [kid] = got
    secret = broker.hold("L1", "sess", kid)
    assert len(secret) == 32 and broker.metadata(kid).state is KeyState.RESERVED
    with pytest.raises(QKDDeviceError):
        broker.hold("L1", "other", kid)                    # mientras está reservada nadie más la obtiene
    with pytest.raises(QKDDeviceError):
        broker.peek(kid, "other")                          # y otro consumidor no puede leerla
    broker.release(kid, "other")                           # ni liberarla
    assert broker.metadata(kid).state is KeyState.RESERVED
    broker.release(kid, "sess")
    assert broker.metadata(kid).state is KeyState.AVAILABLE and broker.hold("L1", "other", kid) == secret   # misma clave, otro consumidor
    assert broker.consume(kid, "other") == secret and broker.metadata(kid).state is KeyState.CONSUMED


def test_a_consumed_key_never_comes_back_through_release_or_hold(tmp_path):
    broker, *_, got = ready(tmp_path)
    [kid] = got
    broker.hold("L1", "sess", kid)
    broker.consume(kid, "sess")
    broker.release(kid, "sess")
    assert broker.metadata(kid).state is KeyState.CONSUMED
    with pytest.raises(QKDDeviceError):
        broker.hold("L1", "sess", kid)
    with pytest.raises(QKDDeviceError):
        broker.peek(kid, "sess")


def test_peek_requires_a_reservation(tmp_path):
    broker, *_, got = ready(tmp_path)
    with pytest.raises(QKDDeviceError):
        broker.peek(got[0], "sess")                        # disponible pero no reservada


def test_hold_of_an_unknown_id_and_by_an_unauthorized_consumer_fail_closed(tmp_path):
    broker, *_ = ready(tmp_path)
    with pytest.raises(PolicyViolation):
        broker.hold("L1", "intruso", "no-existe")
    with pytest.raises(QKDDeviceError):
        broker.hold("L1", "sess", "no-existe")
