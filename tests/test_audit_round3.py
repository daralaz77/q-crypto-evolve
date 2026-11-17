"""Ronda 3 de auditoría independiente (2026-11-16): tres defectos confirmados por lectura de código y su prueba de regresión.

1. `save_anchored` escribía el vault y solo después comprobaba el ancla: un proceso con epoch atrasado dejaba el vault inservible.
2. El MAC de `QKDIngestor` no cubría `source`: una clave SIMULATION se re-etiquetaba como hardware y pasaba la política de producción.
3. `pki._write` creaba la clave privada con el umask y la protegía después con `chmod`, y escribía a través de un symlink plantado.
"""
import os
import stat
from dataclasses import replace

import pytest

from qce.core.errors import AuthenticationFailure, IntegrityError, PolicyViolation
from qce.core.policy import Policy
from qce.key_management import vault
from qce.key_management.keystore import KeyStore, Purpose
from qce.qkd.adapter import QKDIngestor, SimulatedQKDDevice, sign_key
from qce.transport import pki

AUTH = b"a" * 32


def _store(n_ops):
    ks = KeyStore(None, lambda: 1000.0)
    for _ in range(n_ops):
        kid = ks.create(Purpose.ENCRYPT, 3600, secret=b"k" * 32)
        ks.activate(kid)
    return ks


# ---- 1: vault + ancla ----
def test_a_stale_save_is_refused_before_it_touches_the_vault(tmp_path):
    path, anchor = tmp_path / "vault.bin", vault.EpochAnchor(tmp_path / "epoch.json")
    ahead, behind = _store(4), _store(2)  # dos procesos cargaron el mismo vault; A ya avanzó, B va por detrás
    vault.save_anchored(ahead, path, "frase", anchor, n=2**14)
    before = path.read_bytes()
    with pytest.raises(IntegrityError, match="no puede retroceder"):
        vault.save_anchored(behind, path, "frase", anchor, n=2**14)
    assert path.read_bytes() == before  # el vault del proceso adelantado NO se sobrescribió
    assert len(vault.load_anchored(path, "frase", anchor).all_ids()) == 4  # y sigue cargando con el ancla
    assert anchor.read() == ahead.epoch


def test_a_failed_vault_write_does_not_move_the_anchor(tmp_path, monkeypatch):
    path, anchor = tmp_path / "vault.bin", vault.EpochAnchor(tmp_path / "epoch.json")
    vault.save_anchored(_store(1), path, "frase", anchor, n=2**14)
    start = anchor.read()
    monkeypatch.setattr(vault, "save", lambda *a, **k: (_ for _ in ()).throw(OSError("disco lleno")))
    with pytest.raises(OSError):
        vault.save_anchored(_store(3), path, "frase", anchor, n=2**14)
    assert anchor.read() == start  # el ancla solo avanza si el vault ya se guardó


# ---- 2: MAC de QKD cubre `source` ----
def test_relabelling_a_simulated_key_as_hardware_is_detected_by_the_tag():
    ing = QKDIngestor(Policy(allow_simulated_qkd=False), AUTH)
    sim = SimulatedQKDDevice(AUTH, seed=7).fetch_key("p")
    with pytest.raises(PolicyViolation):
        ing.ingest(sim)  # la política de producción rechaza la simulación
    forged = replace(sim, source="hardware:modelo-x", key_id=b"2" * 16)  # mismo tag, otra etiqueta de origen
    forged = replace(forged, tag=sim.tag)
    with pytest.raises(AuthenticationFailure):
        ing.ingest(forged)


def test_the_qkd_tag_binds_source_and_the_exact_qber():
    t = sign_key(AUTH, b"1" * 16, b"k" * 32, 0.03, "hardware:a")
    assert t != sign_key(AUTH, b"1" * 16, b"k" * 32, 0.03, "hardware:b")
    assert t != sign_key(AUTH, b"1" * 16, b"k" * 32, 0.0300001, "hardware:a")  # antes el formato .6f ocultaba diferencias < 1e-6


# ---- 3: PKI escribe la clave privada con 0600 desde el primer instante y sin seguir symlinks ----
def test_private_key_is_never_group_or_world_readable_even_with_a_permissive_umask(tmp_path):
    old = os.umask(0o000)
    try:
        ca_path, ca_key, ca_cert = pki.issue_ca(tmp_path)
        cp, kp = pki.issue_leaf(tmp_path, ca_key, ca_cert, "srv", server=True)
    finally:
        os.umask(old)
    assert stat.S_IMODE(kp.stat().st_mode) == 0o600
    assert stat.S_IMODE(cp.stat().st_mode) == 0o644 and stat.S_IMODE(ca_path.stat().st_mode) == 0o644


def test_a_planted_symlink_is_replaced_not_followed(tmp_path):
    victim = tmp_path / "victima.txt"
    victim.write_text("no tocar")
    ca_path, ca_key, ca_cert = pki.issue_ca(tmp_path)
    (tmp_path / "srv-srv.key").symlink_to(victim)
    _, kp = pki.issue_leaf(tmp_path, ca_key, ca_cert, "srv", server=True)
    assert victim.read_text() == "no tocar"  # el archivo apuntado no se sobrescribió con la clave
    assert not kp.is_symlink() and b"PRIVATE KEY" in kp.read_bytes()
