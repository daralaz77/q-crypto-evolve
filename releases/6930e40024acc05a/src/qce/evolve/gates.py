"""Motor de verificación: GATE 1–6, estados y trinquete de umbrales (nunca se aflojan solos)."""
from __future__ import annotations

import json
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from ..core.chainlog import ChainLog
from ..core.errors import IntegrityError
from ..learning.ledger import Ledger
from ..recovery import release as rel
from ..security import scanners
from . import approvals, mutation

DEFAULT_THRESHOLDS = {"min_tests": 60, "min_mutation_score": 1.0, "max_open_high": 0}
CRITICAL = "critico"


@dataclass
class GateResult:
    gate: str
    status: str  # pass | fail | blocked | skipped
    detail: str
    evidence: dict = field(default_factory=dict)
    seconds: float = 0.0


def _run_pytest(root: Path, args: list[str] | None = None) -> tuple[int, int, str]:
    r = subprocess.run([sys.executable, "-m", "pytest", "-o", "addopts=", "-q", "-p", "no:cacheprovider", *(args or [])],
                       cwd=root, capture_output=True, text=True, timeout=600, env={"PYTHONPATH": str(root), "PATH": "/usr/bin:/bin"})
    m = re.search(r"(\d+) passed", r.stdout)
    return r.returncode, int(m.group(1)) if m else 0, (r.stdout + r.stderr)[-600:]


def load_thresholds(root: Path) -> dict:
    p = root / "gates.json"
    return json.loads(p.read_text()) if p.exists() else dict(DEFAULT_THRESHOLDS)


def evaluate(root: Path, *, version: str, run_mutation: bool = True, mutants: list[str] | None = None,
             run_dep_audit: bool = True) -> dict:
    t_all = time.time()
    root = Path(root)
    th = load_thresholds(root)
    history = ChainLog(root / "learning" / "version_history.jsonl")
    ledger = Ledger(root / "learning" / "incidents.jsonl")
    gates: list[GateResult] = []

    def gate(name, fn):
        t = time.time()
        try:
            g = fn()
        except Exception as exc:  # un fallo de la propia herramienta es un fallo de la puerta, no un "pass"
            g = GateResult(name, "fail", f"error interno de la puerta: {type(exc).__name__}: {exc}")
        g.gate, g.seconds = name, round(time.time() - t, 2)
        gates.append(g)
        return g

    # ---- GATE 1: INTEGRIDAD --------------------------------------------------------------------
    def g1():
        problems = []
        try:
            n = ledger.log.verify()
            history.verify()
        except IntegrityError as exc:
            return GateResult("", "blocked", f"{CRITICAL}: registros de aprendizaje manipulados: {exc}")
        stable = root / "releases" / "STABLE"
        if stable.exists():
            try:
                rel.verify_release(root, json.loads(stable.read_text())["release_id"])
            except Exception as exc:
                problems.append(f"snapshot estable no verifica: {exc}")
        last = history.entries()[-1:] and json.loads(history.entries()[-1]["body"]).get("thresholds")
        if last:  # trinquete: criterios que solo pueden endurecerse
            for k, v in last.items():
                if k == "max_open_high":
                    weaker = th.get(k, 10**9) > v
                else:
                    weaker = th.get(k, -1) < v
                if weaker:
                    problems.append(f"umbral '{k}' debilitado ({v} → {th.get(k)}) sin autorización")
        lock = (root / "requirements.lock")
        if not lock.exists():
            problems.append("falta requirements.lock")
        else:
            frozen = subprocess.run([sys.executable, "-m", "pip", "freeze"], capture_output=True, text=True).stdout.lower().splitlines()
            for line in lock.read_text().lower().splitlines():
                if line and line not in frozen:
                    problems.append(f"dependencia instalada difiere del lock: {line}")
        if problems:
            return GateResult("", "blocked", "; ".join(problems))
        return GateResult("", "pass", f"cadenas de registro íntegras ({n} incidentes/eventos), lock coincide, umbrales no debilitados")

    # ---- GATE 2: FUNCIONALIDAD -----------------------------------------------------------------
    box: dict = {}

    def g2():
        rc, passed, tail = _run_pytest(root)
        box["passed"] = passed
        if rc != 0:
            return GateResult("", "fail", "pruebas fallidas", {"tail": tail})
        if passed < th["min_tests"]:
            return GateResult("", "fail", f"solo {passed} pruebas < mínimo {th['min_tests']} (¿se borraron pruebas?)")
        return GateResult("", "pass", f"{passed} pruebas superadas (incluye vectores NIST ACVP y fuzzing)")

    # ---- GATE 3: SEGURIDAD ---------------------------------------------------------------------
    def g3():
        ev, blocked, failed = {}, [], []
        misuse = scanners.scan_misuse(root)
        bad = [f for f in misuse if f.severity in ("critica", "alta", "media")]
        ev["misuse"] = [f"{f.path}:{f.line} {f.rule}" for f in bad]
        if bad:
            failed.append(f"{len(bad)} malos usos criptográficos")
        secrets = scanners.scan_secrets(root)
        ev["secrets"] = [f"{f.path}:{f.line} {f.rule}" for f in secrets]
        if secrets:
            blocked.append(f"{CRITICAL}: {len(secrets)} posibles secretos en el repositorio")
        if run_mutation:
            m = mutation.run_mutants(root, only=mutants)
            ev["mutation"] = {k: m[k] for k in ("total", "scored", "killed", "score", "survivors", "declared_equivalent", "seconds")}
            if m["score"] < th["min_mutation_score"]:
                failed.append(f"puntuación de mutación {m['score']} < {th['min_mutation_score']}; supervivientes: {m['survivors']}")
        else:
            blocked.append("evidencia insuficiente: prueba de mutación no ejecutada")
        if run_dep_audit:
            d = scanners.audit_dependencies(root)
            ev["dependencies"] = d
            if d["status"] == "vulnerable":
                blocked.append(f"{CRITICAL}: dependencias vulnerables {d['vulnerabilities']}")
            elif d["status"] != "limpia":
                blocked.append(f"evidencia insuficiente: auditoría de dependencias no ejecutada ({d.get('reason')})")
        else:
            blocked.append("evidencia insuficiente: auditoría de dependencias omitida")
        if blocked:
            return GateResult("", "blocked", "; ".join(blocked + failed), ev)
        if failed:
            return GateResult("", "fail", "; ".join(failed), ev)
        return GateResult("", "pass", "sin malos usos, sin secretos, mutación completa, dependencias limpias", ev)

    # ---- GATE 4: REGRESIÓN ---------------------------------------------------------------------
    def g4():
        fails, checked, open_high = [], 0, []
        for inc in ledger.all():
            if inc.get("status") == "resuelto" and inc.get("reproduction_test"):
                rc, _, tail = _run_pytest(root, [inc["reproduction_test"]])
                checked += 1
                if rc != 0:
                    fails.append(inc["incident_id"])
            elif inc.get("severity") in ("critica", "alta") and inc.get("status") != "resuelto":
                open_high.append(inc["incident_id"])
        if len(open_high) > th["max_open_high"]:
            return GateResult("", "blocked", f"{CRITICAL}: incidentes graves sin resolver {open_high}")
        if fails:
            return GateResult("", "fail", f"REGRESIÓN: incidentes ya corregidos reaparecen {fails}", {"regressed": fails})
        return GateResult("", "pass", f"{checked} incidentes históricos reproducidos y siguen corregidos", {"checked": checked})

    gate("G1-INTEGRIDAD", g1)
    gate("G2-FUNCIONALIDAD", g2)
    gate("G3-SEGURIDAD", g3)
    gate("G4-REGRESION", g4)

    # ---- release id (hash del código actual) -----------------------------------------------------
    manifest = rel.build_manifest(root, version, {}, [], {})
    rid = manifest["release_id"]

    # ---- GATE 5: INDEPENDENCIA -----------------------------------------------------------------
    def g5():
        implementers = set(approvals.valid_statements(root, rid, "implementer"))
        reviewers = set(approvals.valid_statements(root, rid, "reviewer"))
        independent = reviewers - implementers
        if not implementers:
            return GateResult("", "skipped", "sin declaración firmada del implementador para este código")
        if not independent:
            return GateResult("", "skipped", "sin revisión firmada de un agente distinto del implementador para este código exacto")
        return GateResult("", "pass", f"revisión independiente válida: {sorted(independent)}")

    # ---- GATE 6: AUTORIZACIÓN ------------------------------------------------------------------
    def g6():
        approvers = approvals.valid_statements(root, rid, "approver")
        if not approvers:
            return GateResult("", "skipped", "sin autorización humana firmada para este código exacto")
        return GateResult("", "pass", f"autorización humana válida: {approvers}")

    gate("G5-INDEPENDENCIA", g5)
    gate("G6-AUTORIZACION", g6)

    # ---- estado final ---------------------------------------------------------------------------
    by = {g.gate[:2]: g for g in gates}
    if any(by[k].status == "blocked" for k in ("G1", "G2", "G3", "G4")):
        state = "BLOCKED"
    elif any(by[k].status == "fail" for k in ("G1", "G2", "G3", "G4")):
        state = "FAILED"
    elif by["G5"].status != "pass":
        state = "REVIEW_REQUIRED"
    elif by["G6"].status != "pass":
        state = "VERIFIED"
    else:
        state = "RELEASE_APPROVED"

    changes_level = None
    report = {
        "version": version, "release_id": rid, "state": state,
        "gates": [g.__dict__ for g in gates],
        "metrics": {"tests_passed": box.get("passed"), "total_seconds": round(time.time() - t_all, 1),
                    "incidents_total": len(ledger.all()), "incidents_resolved": sum(i.get("status") == "resuelto" for i in ledger.all()),
                    "recurring_patterns": ledger.patterns()},
        "thresholds": th,
        "claims_not_made": ["no es una auditoría externa", "no demuestra ausencia de vulnerabilidades",
                            "la resistencia cuántica depende de ML-KEM/ML-DSA (supuestos de dureza), no de este código"],
    }
    history.append({"event": "gates", "version": version, "release_id": rid, "state": state,
                    "tests_passed": box.get("passed"), "thresholds": th,
                    "gate_status": {g.gate: g.status for g in gates}})
    return report
