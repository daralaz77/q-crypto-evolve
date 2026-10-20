"""Cadena de suministro: hashes de dependencias y SBOM CycloneDX, coherentes con requirements.lock (sin red)."""
import json
import subprocess
import sys
from pathlib import Path

import pytest

from qce.core.errors import QCEError
from qce.evolve import supply_chain as SC

ROOT = Path(__file__).resolve().parent.parent
H1, H2, H3 = "a" * 64, "b" * 64, "c" * 64


def fake_fetch(name, version):
    files = {"cffi": [("cffi-2.1.1.tar.gz", H1), ("cffi-2.1.1-cp314-x.whl", H2)], "pycparser": [("pycparser-3.11-py3-none-any.whl", H3)]}[name]
    return {"files": sorted(files), "license": "MIT" if name == "cffi" else "", "summary": ""}


@pytest.fixture()
def proj(tmp_path):
    (tmp_path / "requirements.lock").write_text("cffi==2.1.1\npycparser==3.11\n")
    SC.generate(tmp_path, "9.9.9", fake_fetch)
    return tmp_path


def test_generated_files_are_coherent_with_the_lock_and_match_pips_format(proj):
    assert SC.check(proj) == []
    text = (proj / SC.HASHES_FILE).read_text()
    assert "cffi==2.1.1 \\\n    --hash=sha256:" + H1 in text and "pycparser==3.11 \\\n    --hash=sha256:" + H3 in text
    assert SC.parse_hashes(text) == {"cffi": ("2.1.1", sorted([H1, H2])), "pycparser": ("3.11", [H3])}


def test_sbom_is_cyclonedx_deterministic_and_describes_each_locked_package(proj):
    sb = json.loads((proj / SC.SBOM_FILE).read_text())
    assert sb["bomFormat"] == "CycloneDX" and sb["specVersion"] == "1.5" and sb["metadata"]["component"]["version"] == "9.9.9"
    comps = {c["name"]: c for c in sb["components"]}
    assert comps["cffi"]["purl"] == "pkg:pypi/cffi@2.1.1" and comps["cffi"]["hashes"] == [{"alg": "SHA-256", "content": H1}]   # el hash del sdist
    assert comps["cffi"]["licenses"] == [{"license": {"name": "MIT"}}] and "licenses" not in comps["pycparser"] and "hashes" not in comps["pycparser"]
    first = (proj / SC.SBOM_FILE).read_text()
    SC.generate(proj, "9.9.9", fake_fetch)
    assert (proj / SC.SBOM_FILE).read_text() == first and sb["serialNumber"].startswith("urn:uuid:")      # mismo contenido, mismo número
    SC.generate(proj, "10.0.0", fake_fetch)
    assert json.loads((proj / SC.SBOM_FILE).read_text())["serialNumber"] != sb["serialNumber"]


@pytest.mark.parametrize("mutate,expect", [
    (lambda p: (p / SC.HASHES_FILE).unlink(), "falta requirements.hashes.txt"),
    (lambda p: (p / SC.SBOM_FILE).unlink(), "falta sbom.cdx.json"),
    (lambda p: (p / "requirements.lock").write_text("cffi==2.1.1\npycparser==3.11\nnuevo==1.0\n"), "nuevo no tiene hashes"),
    (lambda p: (p / "requirements.lock").write_text("cffi==2.1.2\npycparser==3.11\n"), "versión 2.1.2 en el lock y 2.1.1 en los hashes"),
    (lambda p: (p / "requirements.lock").write_text("cffi==2.1.1\n"), "pycparser tiene hashes pero no está en el lock"),
    (lambda p: (p / SC.HASHES_FILE).write_text((p / SC.HASHES_FILE).read_text().replace(H3, "zz")), "hashes inválidos"),
    (lambda p: (p / SC.HASHES_FILE).write_text((p / SC.HASHES_FILE).read_text().replace(H3, "ab")), "hashes inválidos"),                 # hexadecimal pero corto
    (lambda p: (p / SC.HASHES_FILE).write_text((p / SC.HASHES_FILE).read_text().replace(H3, "A" * 64)), "hashes inválidos"),            # mayúsculas: pip y PyPI usan minúsculas
    (lambda p: (p / SC.HASHES_FILE).write_text((p / SC.HASHES_FILE).read_text().replace(" \\\n    --hash=sha256:" + H3, "")), "hashes inválidos o ausentes"),
    (lambda p: (p / SC.SBOM_FILE).write_text("{no json"), "no es un SBOM válido"),
    (lambda p: (p / SC.SBOM_FILE).write_text(json.dumps({"components": [{"name": "cffi", "version": "9"}]})), "no coincide con requirements.lock"),
])
def test_check_detects_every_incoherence(proj, mutate, expect):
    mutate(proj)
    assert any(expect in p for p in SC.check(proj)), SC.check(proj)


def test_parser_rejects_options_that_could_redirect_the_installation():
    for bad in ("cffi==2.1.1 --index-url https://evil.example/simple", "cffi==2.1.1 \\\n    --hash=md5:abc", "cffi>=2.1\n", "-r otro.txt", "cffi==2.1.1 --extra-index-url x"):
        with pytest.raises(QCEError):
            SC.parse_hashes(bad)
    assert SC.parse_hashes("# solo un comentario\n\n") == {}


def test_lock_reader_ignores_comments_and_rejects_unrecognised_lines(tmp_path):
    (tmp_path / "requirements.lock").write_text("# nota\n\ncffi==2.1.1\n  PyCparser==3.11  \n")
    assert SC.read_lock(tmp_path) == [("cffi", "2.1.1"), ("pycparser", "3.11")]
    for bad in ("cffi>=2", "cffi", "git+https://x/y.git", "cffi==2.1.1 --hash=sha256:" + H1):
        (tmp_path / "requirements.lock").write_text(bad + "\n")
        with pytest.raises(QCEError):
            SC.read_lock(tmp_path)


def test_fetch_builds_only_pypi_https_urls_from_validated_names(monkeypatch):
    seen = []

    class R:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self, n):
            return json.dumps({"urls": [{"filename": "a.whl", "digests": {"sha256": H1}}, {"filename": "x", "digests": {}}], "info": {"license_expression": "MIT", "summary": "s"}}).encode()

    monkeypatch.setattr(SC.urllib.request, "urlopen", lambda url, timeout: seen.append((url, timeout)) or R())
    meta = SC.fetch_pypi("cffi", "2.1.1")
    assert seen == [("https://pypi.org/pypi/cffi/2.1.1/json", 30.0)] and meta["files"] == [("a.whl", H1)] and meta["license"] == "MIT"
    for name, ver in (("x/../y", "1"), ("cffi", "1/../../etc"), ("cf fi", "1"), ("", "1"), ("cffi", "")):
        with pytest.raises(QCEError):
            SC.fetch_pypi(name, ver)
    assert len(seen) == 1
    monkeypatch.setattr(SC.urllib.request, "urlopen", lambda url, timeout: type("E", (R,), {"read": lambda s, n: json.dumps({"urls": [], "info": {}}).encode()})())
    with pytest.raises(QCEError, match="no devolvió archivos"):
        SC.fetch_pypi("cffi", "2.1.1")


def test_the_committed_lock_hashes_and_sbom_are_coherent():
    assert SC.check(ROOT) == []
    assert {n for n, _ in SC.read_lock(ROOT)} == set(SC.parse_hashes((ROOT / SC.HASHES_FILE).read_text()))


def test_cli_check_reports_a_coherent_supply_chain():
    r = subprocess.run([sys.executable, "-m", "qce", "supply-chain", "--check"], capture_output=True, text=True, cwd=ROOT, env={"PYTHONPATH": str(ROOT), "PATH": "/usr/bin:/bin"}, timeout=60)
    assert r.returncode == 0 and "coherente" in r.stdout
