"""Modelo formal de QCE1 (Tamarin). Las pruebas pesadas solo corren con QCE_FORMAL=1 (≈2 min); las ligeras siempre."""
import json
import os
import re
from pathlib import Path

import pytest

from qce.evolve import formal

ROOT = Path(__file__).resolve().parent.parent
MODEL = ROOT / "formal" / "qce1.spthy"
pytestmark_model = pytest.mark.skipif(not MODEL.exists(), reason="sin carpeta formal/ (p. ej. en el sandbox de mutación)")
heavy = pytest.mark.skipif(os.environ.get("QCE_FORMAL") != "1" or not formal.available(),
                           reason="define QCE_FORMAL=1 y ten tamarin-prover instalado")


@pytestmark_model
def test_expected_verdicts_cover_every_lemma_of_the_model():
    lemmas = set(re.findall(r"^lemma (\w+):", MODEL.read_text(), re.M))
    exp = json.loads((ROOT / "formal" / "expected.json").read_text())
    assert lemmas
    for name, cfg in exp["configs"].items():
        assert set(cfg["verdicts"]) == lemmas, name
        assert set(cfg["defines"]) <= {"BREAKX", "BREAKM", "BREAKE", "BREAKD", "QKD"}


@pytestmark_model
def test_expected_matrix_encodes_the_hybrid_claims():
    """Lo que la especificación afirma, leído del archivo de veredictos (no de una ejecución)."""
    c = {k: v["verdicts"] for k, v in json.loads((ROOT / "formal" / "expected.json").read_text())["configs"].items()}
    safety = ["secrecy_c2s", "secrecy_s2c", "injective_agreement", "no_downgrade", "signature_binds_hello"]
    for single in ("base", "breakX", "breakM", "breakE", "breakD", "breakXE", "breakMD"):
        assert all(c[single][l] == "verified" for l in safety), single  # un KEM y una firma resistentes bastan
    assert c["breakXM"]["secrecy_c2s"] == "falsified" and c["breakED"]["secrecy_c2s"] == "falsified"  # sanidad: el modelo no es vacío
    assert c["breakXM"]["signature_binds_hello"] == "verified"  # la firma aguanta aunque caigan los dos KEM
    assert c["qkd_breakXM"]["secrecy_c2s"] == "verified"  # QKD protege aunque caigan los dos KEM
    assert all(v["executable"] == "verified" for v in c.values())


@heavy
@pytestmark_model
def test_matrix_matches_a_fresh_tamarin_run():
    assert formal.check_matrix(ROOT) == []


@heavy
@pytestmark_model
def test_model_mutants_are_detected():
    assert formal.check_model_mutants(ROOT) == []
