"""Ceremonia de firma humana (G5/G6): la clave la crea la persona fuera del repo, el registro no aprueba y la firma está ligada al código exacto."""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from qce.core.errors import QCEError
from qce.evolve import approvals, ceremony
from qce.pqc.hybrid import SIG_PK_LEN

ROOT = Path(__file__).resolve().parent.parent
RID = "0123456789abcdef"


@pytest.fixture()
def proj(tmp_path):
    p = tmp_path / "proyecto"
    p.mkdir()
    return p


def make(proj, tmp_path, name="ana", role="reviewer"):
    path, pub = ceremony.new_identity(proj, tmp_path / "claves", name)
    ceremony.register(proj, role, name, pub)
    return path, pub


def test_new_identity_creates_a_private_0600_key_outside_the_project_and_never_overwrites(proj, tmp_path):
    path, pub = ceremony.new_identity(proj, tmp_path / "claves", "ana")
    assert path.parent == tmp_path / "claves" and (path.stat().st_mode & 0o777) == 0o600
    assert len(path.read_text().strip()) == ceremony.SEED_HEX_LEN and len(pub) == SIG_PK_LEN
    assert ceremony.load_key(path).public_bytes == pub
    before = path.read_text()
    with pytest.raises(FileExistsError):
        ceremony.new_identity(proj, tmp_path / "claves", "ana")        # no pisa una clave existente
    assert path.read_text() == before
    with pytest.raises(QCEError, match="dentro del repositorio"):
        ceremony.new_identity(proj, proj / "claves", "bea")             # nunca dentro del proyecto
    with pytest.raises(QCEError, match="dentro del repositorio"):
        ceremony.new_identity(proj, proj, "bea")
    assert not list(proj.rglob("*.key"))


@pytest.mark.parametrize("bad", ["", "a/b", "a\\b", ".oculto", "x" * 65])
def test_identity_names_are_validated(proj, tmp_path, bad):
    with pytest.raises(QCEError):
        ceremony.new_identity(proj, tmp_path / "claves", bad)
    ceremony.new_identity(proj, tmp_path / "claves", "x" * 64)           # 64 es el límite inclusivo


def test_a_key_file_readable_by_others_or_malformed_is_refused(proj, tmp_path):
    path, _ = ceremony.new_identity(proj, tmp_path / "claves", "ana")
    path.chmod(0o640)
    with pytest.raises(QCEError, match="accesible a otros"):
        ceremony.load_key(path)
    path.chmod(0o604)
    with pytest.raises(QCEError, match="accesible a otros"):
        ceremony.load_key(path)
    path.chmod(0o600)
    for bad in ("", "zz" * 64, "00" * 63, "00" * 65):
        path.write_text(bad)
        with pytest.raises(QCEError, match="formato"):
            ceremony.load_key(path)


def test_register_only_for_reviewer_and_approver_and_does_not_approve_anything(proj, tmp_path):
    _, pub = ceremony.new_identity(proj, tmp_path / "claves", "ana")
    for role in ("implementer", "otro", ""):
        with pytest.raises(QCEError, match="reviewer"):
            ceremony.register(proj, role, "ana", pub)
    fp = ceremony.register(proj, "reviewer", "ana", pub)
    assert fp == ceremony.fingerprint(pub) and len(fp) == 16
    assert json.loads((proj / "trust" / "registry.json").read_text())["ana"] == {"role": "reviewer", "public_key": pub.hex()}
    assert approvals.valid_statements(proj, RID, "reviewer") == []        # registrar no firma ni aprueba
    _, pub2 = ceremony.new_identity(proj, tmp_path / "claves", "otra")
    with pytest.raises(QCEError):
        ceremony.register(proj, "approver", "ana", pub2)                  # no se rota la clave de una identidad sin revisión humana


def test_parse_public_accepts_hex_or_a_file_and_checks_the_length(proj, tmp_path):
    _, pub = ceremony.new_identity(proj, tmp_path / "claves", "ana")
    f = tmp_path / "ana.pub"
    f.write_text(pub.hex() + "\n")
    assert ceremony.parse_public(pub.hex()) == pub and ceremony.parse_public(str(f)) == pub
    for bad in ("zz", pub.hex()[:-2], pub.hex() + "00", ""):
        with pytest.raises(QCEError):
            ceremony.parse_public(bad)


def test_a_signature_is_valid_only_for_the_exact_release_role_and_registered_key(proj, tmp_path):
    key, pub = make(proj, tmp_path)
    p = ceremony.sign(proj, key, "reviewer", "ana", RID, "accept", "revisado el diseño")
    assert p.exists() and approvals.valid_statements(proj, RID, "reviewer") == ["ana"]
    assert approvals.valid_statements(proj, "ffffffffffffffff", "reviewer") == []     # otro código: no cuenta
    assert approvals.valid_statements(proj, RID, "approver") == []                    # otro rol: no cuenta


def test_signing_checks_identity_role_and_key_before_writing(proj, tmp_path):
    key, _ = make(proj, tmp_path)
    other_key, other_pub = ceremony.new_identity(proj, tmp_path / "claves", "mallory")
    with pytest.raises(QCEError, match="no está registrada"):
        ceremony.sign(proj, key, "reviewer", "nadie", RID, "accept")
    with pytest.raises(QCEError, match="no como"):
        ceremony.sign(proj, key, "approver", "ana", RID, "accept")                   # registrada como reviewer
    with pytest.raises(QCEError, match="no corresponde"):
        ceremony.sign(proj, other_key, "reviewer", "ana", RID, "accept")              # clave ajena firmando como ana
    with pytest.raises(QCEError):
        ceremony.sign(proj, key, "reviewer", "ana", RID, "quizá")
    assert not (proj / "reviews").exists() or not list((proj / "reviews").glob("*.json"))


def test_a_reject_statement_is_kept_and_does_not_count_as_acceptance(proj, tmp_path):
    key, _ = make(proj, tmp_path, role="approver")
    ceremony.sign(proj, key, "approver", "ana", RID, "reject", "no apruebo")
    assert approvals.valid_statements(proj, RID, "approver") == [] and approvals.has_valid_veto(proj, RID, "approver") == ["ana"]


def test_current_release_id_tracks_the_content(proj):
    (proj / "pytest.ini").write_text("[pytest]\n")
    (proj / "qce").mkdir()
    (proj / "qce" / "a.py").write_text("x = 1\n")
    a = ceremony.current_release_id(proj)
    assert ceremony.current_release_id(proj) == a
    (proj / "qce" / "a.py").write_text("x = 2\n")
    assert ceremony.current_release_id(proj) != a


def run_cli(*args, env_extra=None):
    env = {k: v for k, v in os.environ.items() if k != "OPENSSL_CONF"} | {"PYTHONPATH": str(ROOT)} | (env_extra or {})
    return subprocess.run([sys.executable, "-m", "qce", *args], capture_output=True, text=True, cwd=ROOT, env=env, stdin=subprocess.DEVNULL, timeout=60)


def test_cli_refuses_to_sign_without_an_interactive_terminal_and_writes_nothing():
    before = sorted(p.name for p in (ROOT / "reviews").glob("*")) if (ROOT / "reviews").exists() else []
    r = run_cli("sign", "--role", "reviewer", "--signer", "ana", "--key", "/no/existe", "--verdict", "accept", "--release-id", RID)
    assert r.returncode == 2 and "terminal interactiva" in r.stdout
    after = sorted(p.name for p in (ROOT / "reviews").glob("*")) if (ROOT / "reviews").exists() else []
    assert before == after


def test_cli_identity_new_writes_the_key_outside_the_repository(tmp_path):
    r = run_cli("identity", "new", "carla", "--dir", str(tmp_path / "k"))
    assert r.returncode == 0 and "clave privada" in r.stdout and (tmp_path / "k" / "carla.key").exists()
    assert ceremony.parse_public(r.stdout.strip().splitlines()[-1])
    r2 = run_cli("identity", "new", "dora", "--dir", str(ROOT / "dentro"))
    assert r2.returncode == 1 and "dentro del repositorio" in r2.stdout and not (ROOT / "dentro").exists()


def test_a_statement_that_does_not_verify_after_signing_is_not_kept(proj, tmp_path, monkeypatch):
    from qce.core.errors import AuthenticationFailure
    key, _ = make(proj, tmp_path)
    monkeypatch.setattr(approvals, "valid_statements", lambda *a, **k: [])
    with pytest.raises(AuthenticationFailure):
        ceremony.sign(proj, key, "reviewer", "ana", RID, "accept")
    assert not list((proj / "reviews").glob("*.json"))                      # no queda una declaración inservible
    ceremony.sign(proj, key, "reviewer", "ana", RID, "reject")                 # un rechazo no se autoverifica como aceptación
    assert len(list((proj / "reviews").glob("*.json"))) == 1


def test_a_hexadecimal_string_is_never_read_as_a_file_even_if_a_file_with_that_name_exists(proj, tmp_path, monkeypatch):
    _, pub = ceremony.new_identity(proj, tmp_path / "claves", "ana")
    monkeypatch.chdir(tmp_path)
    (tmp_path / "abcd").write_text(pub.hex())              # un archivo llamado como una cadena hexadecimal corta
    with pytest.raises(QCEError, match="longitud"):
        ceremony.parse_public("abcd")                      # es hexadecimal (y corta): no se abre el archivo
    f = tmp_path / "ana.pub"
    f.write_text(pub.hex())
    assert ceremony.parse_public("ana.pub") == pub          # lo que no es hexadecimal sí se trata como ruta
    with pytest.raises(QCEError, match="hexadecimal ni un archivo"):
        ceremony.parse_public("x" * 5000)                    # ruta imposible (nombre demasiado largo): error limpio, no OSError
