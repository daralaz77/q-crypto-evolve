"""Pruebas del panel de solo lectura. Se ejecutan aparte: `python -m pytest panel/tests -o addopts= -q`
(no entran en `tests/`, así que no cambian el release_id)."""
import json
import re
import shutil
import sys
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "panel"))
import data  # noqa: E402
import server  # noqa: E402


def _copy_project(tmp_path: Path) -> Path:
    for rel in ("benchmarks/gates_latest.json", "learning/incidents.jsonl", "trust/registry.json", "gates.json", "THREAT_MODEL.md", "pytest.ini"):
        dst = tmp_path / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(ROOT / rel, dst)
    shutil.copytree(ROOT / "reviews", tmp_path / "reviews")
    return tmp_path


def _serve(root: Path):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), server.make_handler(root))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_port}"


def _get(url, headers=None, method="GET"):
    req = urllib.request.Request(url, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def test_incidents_match_the_projects_own_ledger():
    from qce.learning.ledger import Ledger
    entries, chain = data.read_chain(ROOT / "learning" / "incidents.jsonl")
    mine = {i["incident_id"]: i.get("status") for i in data.incidents(entries)}
    theirs = {i["incident_id"]: i.get("status") for i in Ledger(ROOT / "learning" / "incidents.jsonl").all()}
    assert mine == theirs and chain["ok"]
    from qce.core.chainlog import ChainLog
    assert chain["entradas"] == ChainLog(ROOT / "learning" / "incidents.jsonl").verify()


def test_code_release_id_equals_the_projects_own():
    from qce.recovery.release import build_manifest
    assert data.code_release_id(ROOT) == build_manifest(ROOT, "x", {}, [], {})["release_id"]


def test_tampered_chain_is_reported(tmp_path):
    root = _copy_project(tmp_path)
    p = root / "learning" / "incidents.jsonl"
    lines = p.read_text().splitlines()
    lines[5] = lines[5].replace("INC-", "INX-", 1) if "INC-" in lines[5] else lines[5] + " "
    e = json.loads(lines[5]); e["body"] = e["body"].replace("a", "b", 1); lines[5] = json.dumps(e)
    p.write_text("\n".join(lines) + "\n")
    assert data.snapshot(root)["cadena"]["ok"] is False


@pytest.mark.parametrize("state,statuses,expected", [
    ("RELEASE_APPROVED", ["pass"] * 6, "aprobado"),
    ("RELEASE_APPROVED", ["pass"] * 5 + ["skipped"], "requiere revisión"),  # nunca más verde que sus puertas
    ("REVIEW_REQUIRED", ["pass"] * 5 + ["skipped"], "requiere revisión"),
    ("REVIEW_REQUIRED", ["pass", "fail"], "bloqueado"),
])
def test_verdict_is_never_greener_than_the_report(state, statuses, expected):
    assert data.verdict({"state": state, "gates": [{"status": s} for s in statuses]}) == expected


def test_real_snapshot_shows_review_required_with_g5_skipped():
    s = data.snapshot(ROOT)
    g5 = next(p for p in s["puertas"] if p["puerta"].startswith("G5"))
    assert g5["estado"] == "skipped" and s["veredicto"] == "requiere revisión"


def test_server_is_read_only_and_hardened(tmp_path):
    srv, base = _serve(_copy_project(tmp_path))
    try:
        code, headers, body = _get(base + "/")
        assert code == 200 and b"Q-Crypto Evolve" in body
        assert "script-src 'self'" in headers["Content-Security-Policy"] and "unsafe-inline" not in headers["Content-Security-Policy"]
        assert _get(base + "/api/estado")[0] == 200
        for m in ("POST", "PUT", "DELETE", "PATCH"):
            assert _get(base + "/api/estado", method=m)[0] == 405
        assert _get(base + "/api/estado", headers={"Host": "evil.example"})[0] == 403  # contra DNS rebinding
        assert _get(base + "/../data.py")[0] == 404 and _get(base + "/%2e%2e/data.py")[0] == 404
        assert _get(base + "/server.py")[0] == 404
    finally:
        srv.shutdown()


def test_hostile_incident_text_is_json_data_and_the_frontend_never_uses_html_sinks(tmp_path):
    root = _copy_project(tmp_path)
    from qce.learning.ledger import Incident, Ledger
    L = Ledger(root / "learning" / "incidents.jsonl")
    L.open(Incident(incident_id=L.next_id(), version="t", module="m", symptom="<img src=x onerror=alert(1)><script>alert(2)</script>"))
    srv, base = _serve(root)
    try:
        _, headers, body = _get(base + "/api/estado")
        assert headers["Content-Type"].startswith("application/json")
        assert any("<script>" in (i["sintoma"] or "") for i in json.loads(body)["incidentes"])
    finally:
        srv.shutdown()
    js = (ROOT / "panel" / "static" / "app.js").read_text()
    for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"):
        assert sink not in js
    assert not re.search(r"<script(?![^>]*\bsrc=)", (ROOT / "panel" / "static" / "index.html").read_text())  # sin scripts en línea


def test_panel_never_writes_files(tmp_path):
    root = _copy_project(tmp_path)
    before = {p: p.stat().st_mtime_ns for p in root.rglob("*") if p.is_file()}
    data.snapshot(root)
    srv, base = _serve(root)
    try:
        _get(base + "/api/estado"); _get(base + "/")
    finally:
        srv.shutdown()
    assert {p: p.stat().st_mtime_ns for p in root.rglob("*") if p.is_file()} == before
