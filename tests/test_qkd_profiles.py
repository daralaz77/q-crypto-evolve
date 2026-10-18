"""Perfiles de protocolo QKD: cada familia exige SUS testigos; lo imposible/ausente/sospechoso falla cerrado."""
import math

import pytest

from qce.core.chainlog import ChainLog
from qce.core.errors import PolicyViolation, QKDAnomaly
from qce.core.policy import Policy
from qce.qkd import profiles
from qce.qkd.broker import KeyBroker
from qce.qkd.contract import ErrorCategory, QKDDeviceError
from qce.qkd.devices import DeviceRegistry, SimulatedAdapter, SimulatedLink


def rig(tmp_path, protocol="BB84", faults=(), spec=(), **policy):
    policy = Policy(allow_simulated_qkd=True, **policy)
    reg = DeviceRegistry()
    link = SimulatedLink("L1")
    dev = SimulatedAdapter("devA", link, protocol=protocol, spec=spec, faults=set(faults))
    reg.enroll("devA", "SIMULATION", "sim", dev.firmware, dev.identity.public_bytes, "darwin", protocol=protocol if protocol != "BB84" else "", spec=spec)
    dev.initialize({"registry": reg})
    broker = KeyBroker(policy, reg, ChainLog(tmp_path / "a.jsonl"), allowed_consumers={"L1": {"sess"}})
    return broker, dev, link


def go(tmp_path, **kw):
    broker, dev, link = rig(tmp_path, **kw)
    broker.attach("L1", dev)
    link.generate(1)
    return broker.refill("L1")


SPEC_TF = (("phase_error_max", 0.1),)
SPEC_CV = (("excess_noise_max", 0.05),)


@pytest.mark.parametrize("protocol,spec", [("BB84", ()), ("E91", ()), ("MDI-QKD", ()), ("TF-QKD", SPEC_TF), ("CV-QKD", SPEC_CV), ("DI-QKD", ())])
def test_every_profile_accepts_a_healthy_simulated_device(tmp_path, protocol, spec):
    assert len(go(tmp_path, protocol=protocol, spec=spec)) == 1


def test_unknown_protocol_has_no_profile_and_is_refused_at_attach(tmp_path):
    broker, dev, _ = rig(tmp_path, protocol="MYSTERY-QKD")
    with pytest.raises(PolicyViolation, match="por debajo de la política"):
        broker.attach("L1", dev)  # sin perfil no se confía en ninguna afirmación


@pytest.mark.parametrize("protocol,min_a,ok", [("BB84", 2, False), ("E91", 2, True), ("E91", 3, False), ("MDI-QKD", 3, True),
                                              ("MDI-QKD", 4, False), ("DI-QKD", 4, True)])
def test_policy_minimum_assurance_orders_trust_models(tmp_path, protocol, min_a, ok):
    broker, dev, _ = rig(tmp_path, protocol=protocol, min_assurance=min_a)
    if ok:
        broker.attach("L1", dev)
    else:
        with pytest.raises(PolicyViolation):
            broker.attach("L1", dev)


# ---- BB84 / clave finita --------------------------------------------------------------------------------
def test_bb84_requires_privacy_amplification_and_small_epsilon(tmp_path):
    for fault in ("no_pa", "epsilon_big"):
        with pytest.raises(PolicyViolation):
            go(tmp_path / fault if (tmp_path / fault).mkdir() is None else tmp_path, faults=(fault,))


def test_bb84_decoy_inconsistency_is_an_anomaly_and_quarantines(tmp_path):
    broker, dev, link = rig(tmp_path, faults=("decoy_bad",))
    broker.attach("L1", dev)
    link.generate(1)
    with pytest.raises(QKDAnomaly):
        broker.refill("L1")
    with pytest.raises(QKDAnomaly):
        broker.reserve("L1", "sess")


def test_missing_witness_fails_closed(tmp_path):
    with pytest.raises(QKDDeviceError) as e:
        go(tmp_path, faults=("witness_missing",))
    assert e.value.category is ErrorCategory.INVALID_RESPONSE and "epsilon" in str(e.value)


def test_witness_of_another_key_is_not_accepted_as_evidence(tmp_path):
    broker, dev, link = rig(tmp_path, faults=("stale_witness",))
    broker.attach("L1", dev)
    link.generate(1)
    with pytest.raises(QKDDeviceError) as e:
        broker.refill("L1")
    assert e.value.category is ErrorCategory.INVALID_RESPONSE or e.value.category is ErrorCategory.INTEGRITY_FAILURE
    assert broker.status("L1")["keys"] == {}


# ---- E91 / Bell -------------------------------------------------------------------------------------------------
def test_e91_chsh_bounds():
    P = Policy()
    prof = profiles.PROFILES[profiles.QKDProtocol.E91]
    base = {"key_id": "k", "epsilon": 1e-10, "privacy_amplification": True, "trusted_hops": 0, "qber": 0.02}

    def kinds(s):
        return [f.kind for f in profiles.evaluate(prof, {**base, "chsh_s": s}, P)]
    assert kinds(profiles.TSIRELSON) == []  # el máximo cuántico es válido
    assert kinds(profiles.TSIRELSON + 0.01) == ["invalid"]  # más allá de Tsirelson: dispositivo mentiroso
    assert kinds(2.0 + P.chsh_margin) == ["anomaly"]  # límite inclusivo: no certifica
    assert kinds(2.0 + P.chsh_margin + 1e-6) == []
    assert kinds(1.5) == ["anomaly"] and kinds(-1) == ["invalid"] and kinds(float("nan")) == ["invalid"] and kinds(math.inf) == ["invalid"]


def test_e91_low_chsh_quarantines_and_impossible_value_is_invalid(tmp_path):
    broker, dev, link = rig(tmp_path / "a" if (tmp_path / "a").mkdir() is None else tmp_path, protocol="E91", faults=("chsh_low",))
    broker.attach("L1", dev)
    link.generate(1)
    with pytest.raises(QKDAnomaly):
        broker.refill("L1")
    (tmp_path / "b").mkdir()
    with pytest.raises(QKDDeviceError) as e:
        go(tmp_path / "b", protocol="E91", faults=("chsh_impossible",))
    assert e.value.category is ErrorCategory.INVALID_RESPONSE


# ---- MDI: el relé no es tenedor de claves ---------------------------------------------------------------------------
def test_mdi_relay_that_knows_the_key_contradicts_the_trust_model(tmp_path):
    broker, dev, link = rig(tmp_path, protocol="MDI-QKD", faults=("relay_leaks",))
    broker.attach("L1", dev)
    link.generate(1)
    with pytest.raises(QKDAnomaly, match="relé"):
        broker.refill("L1")


def test_mdi_must_explicitly_deny_relay_key_knowledge():
    prof = profiles.PROFILES[profiles.QKDProtocol.MDI]
    ev = {"key_id": "k", "epsilon": 1e-10, "privacy_amplification": True, "trusted_hops": 0, "qber": 0.02, "decoy_ok": True}
    assert [f.kind for f in profiles.evaluate(prof, {**ev, "relay_holds_key": None}, Policy())] == ["anomaly"]  # "no lo sé" no basta
    assert profiles.evaluate(prof, {**ev, "relay_holds_key": False}, Policy()) == []


# ---- TF: saltos de confianza y ficha ---------------------------------------------------------------------------------
def test_trusted_hops_are_limited_by_policy_and_can_be_allowed_explicitly(tmp_path):
    with pytest.raises(PolicyViolation, match="saltos"):
        go(tmp_path, faults=("hops",))
    (tmp_path / "ok").mkdir()
    assert go(tmp_path / "ok", faults=("hops",), max_trusted_hops=2)


def test_tf_needs_an_approved_spec_and_checks_phase_error(tmp_path):
    with pytest.raises(PolicyViolation, match="ficha"):
        go(tmp_path, protocol="TF-QKD", spec=())  # no se inventa un umbral
    (tmp_path / "x").mkdir()
    broker, dev, link = rig(tmp_path / "x", protocol="TF-QKD", spec=SPEC_TF, faults=("phase_high",))
    broker.attach("L1", dev)
    link.generate(1)
    with pytest.raises(QKDAnomaly, match="fase"):
        broker.refill("L1")


# ---- CV: ruido en exceso y calibración ---------------------------------------------------------------------------------
def test_cv_needs_spec_noise_threshold_and_shot_noise_calibration(tmp_path):
    with pytest.raises(PolicyViolation, match="ficha"):
        go(tmp_path, protocol="CV-QKD")
    for i, fault in enumerate(("noise_high", "uncalibrated")):
        d = tmp_path / str(i)
        d.mkdir()
        broker, dev, link = rig(d, protocol="CV-QKD", spec=SPEC_CV, faults=(fault,))
        broker.attach("L1", dev)
        link.generate(1)
        with pytest.raises(QKDAnomaly):
            broker.refill("L1")


# ---- DI: techo de la escala ---------------------------------------------------------------------------------------------------
def test_di_without_loophole_free_bell_test_is_refused(tmp_path):
    with pytest.raises(PolicyViolation, match="lagunas"):
        go(tmp_path, protocol="DI-QKD", faults=("loopholes",))


def test_assurance_scale_is_ordered_by_trust_model():
    order = [profiles.Assurance.NONE, profiles.Assurance.TRUSTED_DEVICES, profiles.Assurance.ENTANGLEMENT_WITNESSED,
            profiles.Assurance.MEASUREMENT_DEVICE_INDEPENDENT, profiles.Assurance.DEVICE_INDEPENDENT]
    assert order == sorted(order)
    assert profiles.PROFILES[profiles.QKDProtocol.MDI].assurance > profiles.PROFILES[profiles.QKDProtocol.E91].assurance


def test_evaluate_itself_enforces_minimum_assurance_and_rejects_unknown_profile():
    ev = {"key_id": "k", "epsilon": 1e-10, "privacy_amplification": True, "trusted_hops": 0, "qber": 0.02, "decoy_ok": True}
    bb84 = profiles.PROFILES[profiles.QKDProtocol.BB84]
    assert profiles.evaluate(bb84, ev, Policy()) == []
    assert [f.kind for f in profiles.evaluate(bb84, ev, Policy(min_assurance=3))] == ["policy"]
    assert [f.kind for f in profiles.evaluate(profiles.UNKNOWN_PROFILE, ev, Policy())] == ["policy"]
    assert profiles.profile_for("no-existe") is profiles.UNKNOWN_PROFILE


# ---- perfil ETSI-014-KME: la interfaz solo entrega claves; todo lo físico es confianza en el operador ------------------
def test_etsi014_profile_demands_key_size_and_the_approved_hops_and_claims_no_physical_witness():
    from qce.qkd import profiles as PR
    prof = PR.profile_for("ETSI-014-KME")
    pol = Policy(allow_simulated_qkd=True)
    spec = {"trusted_hops": 0}
    assert prof.assurance is PR.Assurance.TRUSTED_DEVICES and prof.per_key_witnesses is False and prof.witnesses == ("key_size_bits",)
    assert PR.evaluate(prof, {"key_size_bits": 256}, pol, spec=spec) == []
    assert PR.evaluate(prof, {"key_size_bits": 128}, pol, spec=spec) == []                            # límite inclusivo
    for bad in (120, 130, True, "256", None, 0):
        assert [f.kind for f in PR.evaluate(prof, {"key_size_bits": bad}, pol, spec=spec)] and PR.evaluate(prof, {"key_size_bits": bad}, pol, spec=spec)[0].kind in ("policy", "invalid")
    assert [f.kind for f in PR.evaluate(prof, {}, pol, spec=spec)] == ["invalid"]                    # falta el testigo
    assert [f.kind for f in PR.evaluate(prof, {"key_size_bits": 256}, pol, spec=None)] == ["policy"]   # sin ficha: no se inventa el dato (y no es «inválido»)
    assert [f.kind for f in PR.evaluate(prof, {"key_size_bits": 256}, pol, spec={"trusted_hops": 1})] == ["policy"]   # 1 salto > 0 de la política
    assert PR.evaluate(prof, {"key_size_bits": 256}, Policy(allow_simulated_qkd=True, max_trusted_hops=1), spec={"trusted_hops": 1}) == []
    assert [f.kind for f in PR.evaluate(prof, {"key_size_bits": 256}, pol, spec={"trusted_hops": -1})] == ["invalid"]
    assert [f.kind for f in PR.evaluate(prof, {"key_size_bits": 256}, pol, spec={"trusted_hops": True})] == ["invalid", "policy"]   # bool no es un número válido: ni como dato ni en la ficha
