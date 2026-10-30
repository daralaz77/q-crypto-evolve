"""Ítem 1.1 de la Fase 1: las dependencias de PRUEBA también van fijadas por hash, y esto se comprueba SIN red."""
import importlib.metadata as md
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
FILE = ROOT / "requirements-test.hashes.txt"
HASH = re.compile(r"^[0-9a-f]{64}$")


def parse(text: str) -> dict[str, tuple[str, list[str]]]:
    """nombre → (versión, [hashes]). Lanza ValueError si una línea no está fijada con `==` o un paquete no tiene al menos un hash válido."""
    out: dict[str, tuple[str, list[str]]] = {}
    cur = None
    for raw in text.replace("\\\n", " ").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"^([A-Za-z0-9_.-]+)==([A-Za-z0-9_.!+-]+)((?:\s+--hash=sha256:[0-9a-f]{64})*)$", line)
        if not m:
            raise ValueError(f"línea no fijada con == y hashes sha256: {line[:60]}")
        hashes = re.findall(r"--hash=sha256:([0-9a-f]{64})", m.group(3))
        if not hashes:
            raise ValueError(f"{m.group(1)} sin hash")
        cur = re.sub(r"[-_.]+", "-", m.group(1)).lower()
        out[cur] = (m.group(2), hashes)
    return out


def test_every_test_dependency_is_pinned_with_hashes():
    pins = parse(FILE.read_text())
    assert {"pytest", "hypothesis"} <= set(pins)
    for name, (ver, hashes) in pins.items():
        assert hashes and all(HASH.match(h) for h in hashes), name


def test_the_installed_test_tools_match_the_pins():
    pins = parse(FILE.read_text())
    for name in ("pytest", "hypothesis"):
        assert md.version(name) == pins[name][0], f"{name}: instalado {md.version(name)} ≠ fijado {pins[name][0]} (¿se actualizó sin regenerar el archivo?)"


def test_the_ci_installs_with_require_hashes():
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
    assert "--require-hashes -r requirements.hashes.txt -r requirements-test.hashes.txt" in ci


@pytest.mark.parametrize("bad", [
    "pytest>=9 \\\n    --hash=sha256:" + "a" * 64,          # no fijada con ==
    "pytest==9.1.1",                                          # sin hash
    "pytest==9.1.1 \\\n    --hash=sha256:" + "z" * 64,       # hash mal formado
])
def test_canary_the_parser_rejects_unpinned_or_unhashed_lines(bad):
    with pytest.raises(ValueError):
        parse(bad)
