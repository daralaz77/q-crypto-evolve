"""Valida la CBOM contra el esquema OFICIAL de CycloneDX 1.6. Se salta si falta `jsonschema` o los esquemas (conformance/fetch_schemas.py)."""
import copy
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT))
pytest.importorskip("jsonschema")
import validate_cbom as vc  # noqa: E402

if not all((vc.CACHE / n).exists() for n in ("bom-1.6.schema.json", "spdx.schema.json", "jsf-0.82.schema.json")):
    pytest.skip("faltan los esquemas: python conformance/fetch_schemas.py", allow_module_level=True)

CBOM = json.loads((ROOT / "benchmarks" / "cbom.cdx.json").read_text())


def test_the_committed_cbom_is_valid_against_the_official_cyclonedx_1_6_schema():
    assert vc.validate(CBOM) == []


def test_canary_an_invalid_primitive_is_reported():
    bad = copy.deepcopy(CBOM)
    next(c for c in bad["components"] if c["cryptoProperties"]["assetType"] == "algorithm")["cryptoProperties"]["algorithmProperties"]["primitive"] = "no-existe"
    assert vc.validate(bad), "el validador no vio una primitiva fuera de la enumeración: no sirve"


def test_canary_a_wrong_asset_type_and_a_missing_required_field_are_reported():
    bad = copy.deepcopy(CBOM)
    bad["components"][0]["cryptoProperties"]["assetType"] = "inventado"
    del bad["specVersion"]
    assert len(vc.validate(bad)) >= 2
