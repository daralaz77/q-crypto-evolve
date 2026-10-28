"""Lectores de SOLO LECTURA de lo que el proyecto ya produce. Nada aquí escribe, ejecuta ni lee claves privadas.

Replica deliberadamente (sin importar `qce`) la lógica del libro de incidentes y del hash del código;
`panel/tests` comprueba que da exactamente lo mismo que `qce` para que no diverjan en silencio.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time
from pathlib import Path

GENESIS = "0" * 64
CODE_GLOBS = ("qce", "tests", "requirements.lock", "requirements.hashes.txt", "sbom.cdx.json", "pytest.ini", "gates.json",
              "THREAT_MODEL.md", "conftest.py", "sitecustomize.py", "usercustomize.py")  # igual que qce/recovery/release.py


def _read_json(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def code_release_id(root: Path) -> str:
    """Hash del código actual con el mismo algoritmo que `qce` (para saber si las puertas siguen vigentes)."""
    files: dict[str, str] = {}
    for g in CODE_GLOBS:
        base = root / g
        everything = [base] if base.is_file() else sorted(base.rglob("*")) if base.is_dir() else []
        for p in everything:
            if p.is_file() and not p.is_symlink() and "__pycache__" not in p.parts and ".hypothesis" not in p.parts:
                files[str(p.relative_to(root))] = hashlib.sha256(p.read_bytes()).hexdigest()
    return hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest()[:16]


def read_chain(path: Path) -> tuple[list[dict], dict]:
    """Entradas del libro y el resultado de verificar la cadena de hashes (sin importar qce)."""
    entries, prev, error = [], GENESIS, None
    try:
        lines = [ln for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    except OSError:
        return [], {"ok": False, "entradas": 0, "cabeza": GENESIS, "error": "no se pudo leer el libro"}
    for n, line in enumerate(lines):
        try:
            e = json.loads(line)
            digest = hashlib.sha256(f"{n}|{e['ts']!r}|{prev}|{e['body']}".encode()).hexdigest()
            if e["i"] != n or e["prev"] != prev or not hmac.compare_digest(e["hash"], digest):
                raise ValueError("hash o enlace no coincide")
        except (ValueError, KeyError, TypeError):
            error = f"cadena rota en la entrada {n}"
            break
        entries.append(e)
        prev = e["hash"]
    return entries, {"ok": error is None, "entradas": len(entries), "cabeza": prev, "error": error}


def incidents(entries: list[dict]) -> list[dict]:
    state: dict[str, dict] = {}
    for e in entries:
        try:
            body = json.loads(e["body"])
            state.setdefault(body["incident_id"], {}).update(body)
        except (ValueError, KeyError, TypeError):
            continue
    return list(state.values())


def verdict(gates_report: dict) -> str:
    """Nunca más verde que el informe: solo «aprobado» si el estado lo dice Y todas las puertas pasan."""
    gates = gates_report.get("gates", [])
    if gates_report.get("state") == "RELEASE_APPROVED" and gates and all(g.get("status") == "pass" for g in gates):
        return "aprobado"
    if any(g.get("status") in ("fail", "failed", "blocked") for g in gates):
        return "bloqueado"
    return "requiere revisión"


def snapshot(root: Path) -> dict:
    gates_path = root / "benchmarks" / "gates_latest.json"
    report = _read_json(gates_path, {})
    entries, chain = read_chain(root / "learning" / "incidents.jsonl")
    incs = incidents(entries)
    mutation = next((g.get("evidence", {}).get("mutation") for g in report.get("gates", [])
                     if g.get("gate", "").startswith("G3") and g.get("evidence", {}).get("mutation")), None)
    reviews = []
    for p in sorted((root / "reviews").glob("*.json")):
        d = _read_json(p, {})
        reviews.append({"rol": d.get("role"), "firmante": d.get("signer"), "release_id": d.get("release_id"),
                        "veredicto": d.get("verdict"), "notas": d.get("notes", ""), "archivo": p.name})
    trust = _read_json(root / "trust" / "registry.json", {})
    current = code_release_id(root)
    gates_rid = report.get("release_id")
    for r in reviews:
        r["vigente"] = r["release_id"] == current
    total = (report.get("metrics") or {}).get("total_seconds") or 0
    return {
        "generado": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "veredicto": verdict(report),
        "estado": report.get("state", "SIN DATOS"),
        "version": report.get("version"),
        "release_id_puertas": gates_rid,
        "release_id_codigo": current,
        "puertas_vigentes": bool(gates_rid) and gates_rid == current,
        "puertas_antiguedad_s": int(time.time() - gates_path.stat().st_mtime) if gates_path.exists() else None,
        "puertas": [{"puerta": g.get("gate"), "estado": g.get("status"), "detalle": g.get("detail"),
                     "segundos": g.get("seconds", 0),
                     "pct": round(100 * g.get("seconds", 0) / total, 1) if total else 0} for g in report.get("gates", [])],
        "metricas": {k: v for k, v in (report.get("metrics") or {}).items() if k != "recurring_patterns"},
        "patrones": (report.get("metrics") or {}).get("recurring_patterns", []),
        "umbrales": report.get("thresholds", {}),
        "no_afirma": report.get("claims_not_made", []),
        "mutacion": mutation,
        "cadena": chain,
        "incidentes": [{"id": i.get("incident_id"), "modulo": i.get("module"), "severidad": i.get("severity"),
                        "estado": i.get("status"), "sintoma": i.get("symptom"), "causa": i.get("root_cause"),
                        "categoria": i.get("root_cause_category"), "certeza": i.get("confidence"),
                        "fecha": i.get("date"), "prueba": i.get("reproduction_test"), "reparacion": i.get("repair"),
                        "riesgos": i.get("residual_risks")} for i in incs],
        "firmas": reviews,
        "confianza": [{"nombre": k, "rol": v.get("role")} for k, v in trust.items()],
    }
