"""Pruebas de la demo didáctica: `python -m pytest site/tests -o addopts= -q` (fuera de `tests/`, no cambia el release_id)."""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "site"))
import build  # noqa: E402


def test_traces_file_is_up_to_date_with_the_recorded_sources():
    js = (ROOT / "site" / "trazas.js").read_text(encoding="utf-8")
    embedded = json.loads(js.removeprefix("window.TRAZAS = ").rstrip().removesuffix(";"))
    assert embedded == build.build(), "regenera con: python site/build.py"


def test_every_displayed_trace_line_comes_from_the_real_quickstart_output():
    real = (ROOT / "examples" / "SALIDA_ESPERADA.txt").read_text(encoding="utf-8")
    for paso in build.build()["quickstart"]["pasos"]:
        for linea in paso["lineas"]:
            assert f"[{paso['n']}] {linea}" in real


def test_page_has_no_html_sinks_no_external_requests_and_labels_simulation():
    js = (ROOT / "site" / "demo.js").read_text(encoding="utf-8")
    for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"):
        assert sink not in js
    page = (ROOT / "site" / "index.html").read_text(encoding="utf-8") + (ROOT / "site" / "demo.css").read_text(encoding="utf-8")
    assert not re.search(r"""(?:src|href)=["']https?://(?!github\.com/daralaz77|doi\.org/10\.5281)""", page), "recursos externos no permitidos"
    assert "http://" not in page and "@import" not in page
    assert "Simulación de laboratorio" in page and "ninguna persona ajena al proyecto ha revisado" in page


def test_limits_section_lists_everything_the_demo_declares_not_demonstrated():
    for item in build.build()["demo"]["no_demostrado"]:
        assert item in json.dumps(build.build(), ensure_ascii=False)
