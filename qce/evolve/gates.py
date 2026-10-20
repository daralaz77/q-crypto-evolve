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
from ..core.errors import IntegrityError, QCEError
from ..learning.ledger import Ledger, check_test_ref
from ..recovery import release as rel
from ..security import scanners
from . import approvals, mutation

DEFAULT_THRESHOLDS = {"min_tests": 60, "min_mutation_score": 1.0, "max_open_high": 0, "min_mutants": 0, "max_declared_equivalent": 10**6}
CRITICAL = "critico"


@dataclass
class GateResult:
    gate: str
    status: str  # pass | fail | blocked | skipped
    detail: str
    evidence: dict = field(default_factory=dict)
    seconds: float = 0.0


def _purge_bytecode(root: Path) -> None:
    """Un .pyc plantado no entra en el release_id pero Python lo ejecutaría: se borra y se ejecuta con -B."""
    import shutil
    for top in ("qce", "tests"):
        for d in (root / top).rglob("__pycache__"):
            shutil.rmtree(d, ignore_errors=True)


def _run_pytest(root: Path, args: list[str] | None = None) -> tuple[int, int, str]:
    _purge_bytecode(root)
    r = subprocess.run([sys.executable, "-B", "-m", "pytest", "-o", "addopts=", "-q", "-p", "no:cacheprovider", *(args or [])],
                       cwd=root, capture_output=True, text=True, timeout=600, env={"PYTHONPATH": str(root), "PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1"})
    m = re.search(r"(\d+) passed", r.stdout)
    return r.returncode, int(m.group(1)) if m else 0, (r.stdout + r.stderr)[-600:]


def strictest_baseline(history: ChainLog) -> dict:
    """Combina TODO el historial: el umbral vigente es el más estricto que alguna vez se registró."""
    base: dict = {}
    for e in history.entries():
        for k, v in (json.loads(e["body"]).get("thresholds") or {}).items():
            if not isinstance(v, (int, float)) or isinstance(v, bool) or v != v:
                continue  # nunca un NaN como baseline
            if k not in base:
                base[k] = v
            else:
                base[k] = min(base[k], v) if k.startswith("max_") else max(base[k], v)
    return base


THRESHOLD_RULES = {  # clave: (tipo, mínimo, máximo)
    "min_tests": (int, 1, 10**6), "min_mutation_score": (float, 0.0, 1.0), "max_open_high": (int, 0, 10**6),
    "min_mutants": (int, 0, 10**6), "max_declared_equivalent": (int, 0, 10**6),
}


def validate_thresholds(th: dict) -> dict:
    """NaN/inf/tipos raros anulan toda comparación (a < NaN es siempre False): se rechazan antes de usarse."""
    for k, (typ, lo, hi) in THRESHOLD_RULES.items():
        v = th.get(k)
        ok = isinstance(v, (int, float)) and not isinstance(v, bool) and v == v and abs(v) != float("inf") and lo <= v <= hi
        if typ is int and ok and v != int(v):
            ok = False
        if not ok:
            raise QCEError(f"umbral '{k}' inválido o ausente: {v!r}")
    return th


def load_thresholds(root: Path) -> dict:
    p = root / "gates.json"
    th = json.loads(p.read_text()) if p.exists() else dict(DEFAULT_THRESHOLDS)
    return validate_thresholds(th)


@dataclass
class _Ctx:
    """Lo que necesitan las puertas: una sola estructura en vez de variables capturadas por clausuras."""
    root: Path
    th: dict
    ledger: Ledger
    history: ChainLog
    run_mutation: bool = True
    mutants: list[str] | None = None
    run_dep_audit: bool = True
    rid: str = ""
    passed: int | None = None


# ---- GATE 1: INTEGRIDAD --------------------------------------------------------------------------
def _g1_integrity(c: _Ctx) -> GateResult:
    problems = []
    try:
        n = c.ledger.log.verify()
        c.history.verify()
        if (c.root / "learning" / "tasks.jsonl").exists():
            ChainLog(c.root / "learning" / "tasks.jsonl").verify()
    except IntegrityError as exc:
        return GateResult("", "blocked", f"{CRITICAL}: registros de aprendizaje manipulados: {exc}")
    stable = c.root / "releases" / "STABLE"
    if stable.exists():
        try:
            rel.verify_release(c.root, json.loads(stable.read_text())["release_id"])
        except Exception as exc:
            problems.append(f"snapshot estable no verifica: {exc}")
    for k, v in strictest_baseline(c.history).items():  # trinquete contra el MÁS estricto jamás registrado
        lower_is_stricter = k.startswith("max_")
        weaker = c.th.get(k, 10**9) > v if lower_is_stricter else c.th.get(k, -1) < v
        if weaker:
            problems.append(f"umbral '{k}' debilitado ({v} → {c.th.get(k)}) sin autorización")
    for boot in ("conftest.py", "sitecustomize.py", "usercustomize.py"):
        if (c.root / boot).exists():
            problems.append(f"archivo de arranque de pruebas no permitido en la raíz: {boot}")
    lock = (c.root / "requirements.lock")
    if not lock.exists():
        problems.append("falta requirements.lock")
    else:
        frozen = subprocess.run([sys.executable, "-m", "pip", "freeze"], capture_output=True, text=True).stdout.lower().splitlines()
        for line in lock.read_text().lower().splitlines():
            if line and line not in frozen:
                problems.append(f"dependencia instalada difiere del lock: {line}")
    from . import supply_chain
    problems += supply_chain.check(c.root)   # hashes de dependencias y SBOM coherentes con el lock (sin red)
    if problems:
        return GateResult("", "blocked", "; ".join(problems))
    return GateResult("", "pass", f"cadenas de registro íntegras ({n} incidentes/eventos), lock coincide, hashes y SBOM coherentes, umbrales no debilitados")


# ---- GATE 2: FUNCIONALIDAD -----------------------------------------------------------------------
def _g2_functionality(c: _Ctx) -> GateResult:
    rc, passed, tail = _run_pytest(c.root)
    c.passed = passed
    if rc != 0:
        return GateResult("", "fail", "pruebas fallidas", {"tail": tail})
    if passed < c.th["min_tests"]:
        return GateResult("", "fail", f"solo {passed} pruebas < mínimo {c.th['min_tests']} (¿se borraron pruebas?)")
    return GateResult("", "pass", f"{passed} pruebas superadas (incluye vectores NIST ACVP y fuzzing)")


# ---- GATE 3: SEGURIDAD ---------------------------------------------------------------------------
def _g3_security(c: _Ctx) -> GateResult:
    ev, blocked, failed = {}, [], []
    misuse = scanners.scan_misuse(c.root)
    bad = [f for f in misuse if f.severity in ("critica", "alta", "media")]
    ev["misuse"] = [f"{f.path}:{f.line} {f.rule}" for f in bad]
    if bad:
        failed.append(f"{len(bad)} malos usos criptográficos")
    secrets = scanners.scan_secrets(c.root)
    ev["secrets"] = [f"{f.path}:{f.line} {f.rule}" for f in secrets]
    if secrets:
        blocked.append(f"{CRITICAL}: {len(secrets)} posibles secretos en el repositorio")
    if c.run_mutation:
        m = mutation.run_mutants(c.root, only=c.mutants)
        ev["mutation"] = {k: m[k] for k in ("total", "scored", "killed", "score", "survivors", "declared_equivalent", "seconds", "canary_ok")}
        if not m.get("canary_ok"):
            failed.append("el canario del arnés de mutación falta o fue 'detectado': el resultado no es fiable")
        if m["scored"] < c.th["min_mutants"]:
            failed.append(f"solo {m['scored']} mutantes puntuables < mínimo {c.th['min_mutants']} (¿se borraron mutantes?)")
        if len(m["declared_equivalent"]) > c.th["max_declared_equivalent"]:
            failed.append(f"{len(m['declared_equivalent'])} mutantes declarados equivalentes > máximo {c.th['max_declared_equivalent']}")
        if m["score"] < c.th["min_mutation_score"]:
            failed.append(f"puntuación de mutación {m['score']} < {c.th['min_mutation_score']}; supervivientes: {m['survivors']}")
    else:
        blocked.append("evidencia insuficiente: prueba de mutación no ejecutada")
    if c.run_dep_audit:
        d = scanners.audit_dependencies(c.root)
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


# ---- GATE 4: REGRESIÓN ---------------------------------------------------------------------------
def _g4_regression(c: _Ctx) -> GateResult:
    fails, checked, open_high = [], 0, []
    for inc in c.ledger.all():
        if inc.get("status") == "resuelto" and not inc.get("reproduction_test"):
            fails.append(inc["incident_id"])  # "resuelto" sin prueba de regresión no es resuelto
            continue
        if inc.get("status") == "resuelto" and inc.get("reproduction_test"):
            checked += 1
            try:
                check_test_ref(inc["reproduction_test"])  # sin inyección de opciones de pytest
                rc, passed_n, tail = _run_pytest(c.root, ["--", inc["reproduction_test"]])
            except Exception:
                rc, passed_n = 1, 0
            if rc != 0 or passed_n < 1:  # "0 pruebas ejecutadas" no es una regresión superada
                fails.append(inc["incident_id"])
        elif inc.get("severity") in ("critica", "alta") and inc.get("status") != "resuelto":
            open_high.append(inc["incident_id"])
    if len(open_high) > c.th["max_open_high"]:
        return GateResult("", "blocked", f"{CRITICAL}: incidentes graves sin resolver {open_high}")
    if fails:
        return GateResult("", "fail", f"REGRESIÓN: incidentes ya corregidos reaparecen {fails}", {"regressed": fails})
    return GateResult("", "pass", f"{checked} incidentes históricos reproducidos y siguen corregidos", {"checked": checked})


# ---- GATE 5: INDEPENDENCIA -----------------------------------------------------------------------
def _g5_independence(c: _Ctx) -> GateResult:
    implementers = set(approvals.valid_statements(c.root, c.rid, "implementer"))
    reviewers = set(approvals.valid_statements(c.root, c.rid, "reviewer"))
    independent = reviewers - implementers
    if not implementers:
        return GateResult("", "skipped", "sin declaración firmada del implementador para este código")
    if not independent:
        return GateResult("", "skipped", "sin revisión firmada de un agente distinto del implementador para este código exacto")
    return GateResult("", "pass", f"revisión independiente válida: {sorted(independent)}")


# ---- GATE 6: AUTORIZACIÓN ------------------------------------------------------------------------
def _g6_authorization(c: _Ctx) -> GateResult:
    approvers = approvals.valid_statements(c.root, c.rid, "approver")
    if not approvers:
        return GateResult("", "skipped", "sin autorización humana firmada para este código exacto")
    return GateResult("", "pass", f"autorización humana válida: {approvers}")


def _final_state(gates: list[GateResult]) -> str:
    by = {g.gate[:2]: g for g in gates}
    if any(by[k].status == "blocked" for k in ("G1", "G2", "G3", "G4")):
        return "BLOCKED"
    if any(by[k].status == "fail" for k in ("G1", "G2", "G3", "G4")):
        return "FAILED"
    if by["G5"].status != "pass":
        return "REVIEW_REQUIRED"
    if by["G6"].status != "pass":
        return "VERIFIED"
    return "RELEASE_APPROVED"


def evaluate(root: Path, *, version: str, run_mutation: bool = True, mutants: list[str] | None = None,
             run_dep_audit: bool = True) -> dict:
    t_all = time.time()
    root = Path(root)
    try:
        th = load_thresholds(root)
    except (QCEError, ValueError, TypeError) as exc:  # umbrales corruptos = puerta cerrada, no excepción
        return {"version": version, "release_id": "", "state": "BLOCKED", "metrics": {},
                "gates": [{"gate": "G1-INTEGRIDAD", "status": "blocked", "detail": f"gates.json inválido: {exc}", "evidence": {}, "seconds": 0.0}],
                "thresholds": {}, "claims_not_made": []}
    c = _Ctx(root, th, Ledger(root / "learning" / "incidents.jsonl"), ChainLog(root / "learning" / "version_history.jsonl"),
             run_mutation=run_mutation, mutants=mutants, run_dep_audit=run_dep_audit)
    gates: list[GateResult] = []

    def gate(name, fn):
        t = time.time()
        try:
            g = fn(c)
        except Exception as exc:  # un fallo de la propia herramienta es un fallo de la puerta, no un "pass"
            g = GateResult(name, "fail", f"error interno de la puerta: {type(exc).__name__}: {exc}")
        g.gate, g.seconds = name, round(time.time() - t, 2)
        gates.append(g)
        return g

    gate("G1-INTEGRIDAD", _g1_integrity)
    gate("G2-FUNCIONALIDAD", _g2_functionality)
    gate("G3-SEGURIDAD", _g3_security)
    gate("G4-REGRESION", _g4_regression)

    # ---- release id (hash del código actual) -----------------------------------------------------
    c.rid = rel.build_manifest(root, version, {}, [], {})["release_id"]
    gate("G5-INDEPENDENCIA", _g5_independence)
    gate("G6-AUTORIZACION", _g6_authorization)

    state = _final_state(gates)
    rid, ledger, history = c.rid, c.ledger, c.history
    report = {
        "version": version, "release_id": rid, "state": state,
        "gates": [g.__dict__ for g in gates],
        "metrics": {"tests_passed": c.passed, "total_seconds": round(time.time() - t_all, 1),
                    "incidents_total": len(ledger.all()), "incidents_resolved": sum(i.get("status") == "resuelto" for i in ledger.all()),
                    "recurring_patterns": ledger.patterns()},
        "thresholds": th,
        "claims_not_made": ["no es una auditoría externa", "no demuestra ausencia de vulnerabilidades",
                            "la resistencia cuántica depende de ML-KEM/ML-DSA (supuestos de dureza), no de este código"],
    }
    base = strictest_baseline(history)
    merged = {**th, **{k: (min(th[k], base[k]) if k.startswith("max_") else max(th[k], base[k])) for k in base if k in th}}
    history.append({"event": "gates", "version": version, "release_id": rid, "state": state,
                    "tests_passed": c.passed, "thresholds": merged,  # nunca se registra un umbral más débil
                    "gate_status": {g.gate: g.status for g in gates}})
    return report

