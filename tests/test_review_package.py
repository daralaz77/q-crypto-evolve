"""El paquete de revisión externa debe ser completo, reproducible, verificable y no filtrar secretos."""
import json
import zipfile
from pathlib import Path

import pytest

from qce.evolve import review_package as rp
from qce.security import scanners

ROOT = Path(__file__).resolve().parent.parent
needs_repo = pytest.mark.skipif(not (ROOT / "review" / "LEEME.md").exists(), reason="solo en el repositorio completo (no dentro del propio paquete)")

REQUIRED = {"LEEME.md", "PREGUNTAS_ABIERTAS.md", "REPRODUCCION.md", "GUIA_PARA_ENVIAR.md", "qce/evolve/ceremony.py", "tests/test_ceremony.py", "PLANTILLA_INFORME.md", "docs/QCE1_SPEC.md", "docs/QCE1_FORMAL.md",
            "docs/QCE1_CONFORMANCE.md", "formal/qce1.spthy", "formal/expected.json", "LIMITATIONS.md", "THREAT_MODEL.md",
            "docs/QKD_LAYER_SPEC.md", "formal/qil1.spthy", "formal/expected_qil1.json", "qce/transport/qkd_layer.py", "tests/test_qil_conformance.py",
            "qce/protocols/session.py", "qce/pqc/hybrid.py", "tests/test_conformance.py", "requirements.lock", "requirements-test.lock",
            "PACKAGE_INFO.json", "MANIFEST.sha256"}


@pytest.fixture(scope="module")
def built(tmp_path_factory):
    out = tmp_path_factory.mktemp("pkg")
    path, digest = rp.build(ROOT, out)
    return path, digest, out


@needs_repo
def test_package_contains_everything_a_reviewer_needs(built):
    names = set(zipfile.ZipFile(built[0]).namelist())
    assert REQUIRED <= names, REQUIRED - names


@needs_repo
def test_package_excludes_environments_keys_and_build_artifacts(built):
    for n in zipfile.ZipFile(built[0]).namelist():
        parts = set(Path(n).parts)
        assert not parts & {".venv", "__pycache__", "releases", "reviews", "trust", "benchmarks", "dist", ".hypothesis"}, n
        assert not n.endswith((".bin", ".pem", ".key", ".pyc")), n


@needs_repo
def test_build_is_byte_for_byte_reproducible(built, tmp_path):
    _, digest2 = rp.build(ROOT, tmp_path)
    assert digest2 == built[1]


@needs_repo
def test_manifest_verifies_and_detects_tampering_additions_and_removals(built, tmp_path):
    assert rp.verify(built[0]) == []
    src = zipfile.ZipFile(built[0])
    for case in ("alterado", "añadido", "quitado"):
        bad = tmp_path / f"{case}.zip"
        with zipfile.ZipFile(bad, "w") as z:
            for n in src.namelist():
                data = src.read(n)
                if case == "alterado" and n == "qce/protocols/session.py":
                    data += b"\n# puerta trasera\n"
                if case == "quitado" and n == "formal/qce1.spthy":
                    continue
                z.writestr(n, data)
            if case == "añadido":
                z.writestr("extra.py", b"print(1)")
        assert rp.verify(bad), case


@needs_repo
def test_unsafe_paths_in_a_package_are_reported(tmp_path):
    bad = tmp_path / "x.zip"
    with zipfile.ZipFile(bad, "w") as z:
        z.writestr("MANIFEST.sha256", "")
        z.writestr("../evil.txt", b"x")
    assert any("peligrosa" in p for p in rp.verify(bad))


@needs_repo
def test_no_secrets_in_the_package(built, tmp_path):
    zipfile.ZipFile(built[0]).extractall(tmp_path)
    assert scanners.scan_secrets(tmp_path) == []


@needs_repo
def test_package_declares_that_it_is_unsigned_and_gives_the_code_identity(built):
    info = json.loads(zipfile.ZipFile(built[0]).read("PACKAGE_INFO.json"))
    assert info["firmado"] is False and len(info["release_id_del_codigo"]) == 16 and info["tamarin_esperado"] == "1.12.0"


@needs_repo
def test_reviewer_docs_state_the_authorship_and_the_missing_human_review():
    leeme = (ROOT / "review" / "LEEME.md").read_text()
    assert "Toda la autoría es de instancias de Claude" in leeme and "no es** una revisión humana independiente" in leeme
    assert "[CONTACTO" in leeme  # el contacto lo pone una persona; no se inventa


@needs_repo
def test_package_carries_every_test_vector_file_and_every_file_the_tests_read(built):
    """La reproducción desde cero destapó que faltaba un archivo de vectores: ninguno de los datos que leen las pruebas puede quedar fuera del paquete."""
    names = set(zipfile.ZipFile(built[0]).namelist())
    for f in (ROOT / "tests" / "vectors").glob("*.json"):
        assert f"tests/vectors/{f.name}" in names, f.name
    for f in (ROOT / "tests" / "helpers").glob("*"):                      # ayudantes que las pruebas compilan o ejecutan (no son *.py)
        assert f"tests/helpers/{f.name}" in names, f.name
    import re
    for test in (ROOT / "tests").glob("test_*.py"):
        for m in re.finditer(r'"(vectors/[\w.-]+|formal/[\w.-]+|docs/[\w.-]+)"', test.read_text()):
            rel = m.group(1) if m.group(1).startswith(("formal/", "docs/")) else "tests/" + m.group(1)
            if (ROOT / rel).exists():
                assert rel in names, f"{test.name} lee {rel} y no está en el paquete"
