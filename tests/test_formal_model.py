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


QIL = ROOT / "formal" / "qil1.spthy"
needs_qil = pytest.mark.skipif(not QIL.exists(), reason="sin formal/qil1.spthy")


@needs_qil
def test_qil1_expected_verdicts_cover_every_lemma_and_encode_its_claims():
    lemmas = set(re.findall(r"^lemma (\w+):", QIL.read_text(), re.M))
    exp = json.loads((ROOT / "formal" / "expected_qil1.json").read_text())["configs"]
    for name, cfg in exp.items():
        assert set(cfg["verdicts"]) == lemmas, name
        assert set(cfg["defines"]) <= {"BREAKTLS", "REVEALQKD", "NOBIND"}, name
    V = {n: c["verdicts"] for n, c in exp.items()}
    safety = [l for l in lemmas if l not in ("executable", "rogue_relay_reaches_done", "later_qkd_leak_exposes_past_session")]
    for name, v in V.items():
        for l in safety:
            expected = "falsified" if (name.startswith("nobind") and "breakTLS" in name and not name.startswith("nobind_revealQkd")
                                        and l in ("channel_agreement", "server_agreement")) or (name == "nobind_revealQkd_breakTLS" and l in ("channel_agreement", "server_agreement")) else "verified"
            assert v[l] == expected, (name, l)
    # la ligadura es lo que frena la retransmisión con certificado falso
    assert V["breakTLS"]["rogue_relay_reaches_done"] == "falsified" and V["nobind_breakTLS"]["rogue_relay_reaches_done"] == "verified"
    # límite medido (regresión del lema mal planteado): solo sin ligadura, con TLS roto y K filtrada después queda expuesta una sesión pasada
    assert [n for n, v in V.items() if v["later_qkd_leak_exposes_past_session"] == "verified"] == ["nobind_revealQkd_breakTLS"]


@needs_qil
def test_the_past_session_leak_lemma_excludes_an_earlier_reveal():
    """El lema se planteó mal una vez: la regla de revelar es repetible y bastaba revelar ANTES para que fuera trivialmente cierto."""
    text = QIL.read_text()
    block = text[text.index("lemma later_qkd_leak_exposes_past_session"):]
    assert "not (Ex #r0. RevealQkd(kid) @ r0 & r0 < i)" in block.split("end")[0]


@heavy
def test_qil1_matrix_and_model_mutants_match_the_expected_verdicts():
    assert formal.check_matrix(ROOT, model_name="qil1.spthy", expected_name="expected_qil1.json") == []
    assert formal.check_model_mutants(ROOT, "qil1.spthy", formal.QIL1_MODEL_MUTANTS) == []
