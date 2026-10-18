"""Cada prueba citada en THREAT_MODEL.md debe existir; las amenazas sin prueba deben declararse como tales."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TM = (ROOT / "THREAT_MODEL.md").read_text()


def test_every_cited_test_exists():
    cited = set(re.findall(r"`(tests/[\w./]+)::(\w+)`", TM))
    assert len(cited) >= 25
    for path, name in cited:
        assert re.search(rf"^def {name}\(", (ROOT / path).read_text(), re.M), f"{path}::{name} no existe"


def test_threats_without_tests_are_declared():
    rows = [r for r in TM.splitlines() if re.match(r"\| T\d+ ", r)]
    assert len(rows) >= 19
    for r in rows:
        assert "`tests/" in r or "SIN PRUEBA" in r, f"amenaza sin prueba ni declaración: {r[:40]}"
