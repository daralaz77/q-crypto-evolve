"""Máquina de estados del cambio (v3) con registro estructurado de tarea y reglas de independencia.

Cada transición se anexa a una cadena de hashes (learning/tasks.jsonl). El estado actual se
reconstruye SIEMPRE desde el registro: no hay estado en memoria que un agente pueda alterar.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable

from ..core.chainlog import ChainLog
from ..core.errors import QCEError

MAIN = ["CREATED", "ANALYZED", "APPROVED_FOR_IMPLEMENTATION", "IMPLEMENTED", "TESTING",
        "INDEPENDENT_REVIEW", "VERIFIED", "RELEASE_REVIEW", "RELEASE_APPROVED"]
ALT = ["FAILED", "BLOCKED", "REVIEW_REQUIRED", "ROLLED_BACK", "ABANDONED"]
ROLES = {"ARCHITECT", "CRYPTO-ENGINEER", "IMPLEMENTER", "ADVERSARIAL-AUDITOR", "VERIFIER", "REPAIR-ENGINEER",
         "MEMORY-STEWARD", "RELEASE-GUARDIAN", "SECURITY-CHAIR", "HUMAN"}

# Transiciones permitidas (además del avance lineal, cualquier estado vivo puede ir a FAILED/BLOCKED/...)
NEXT = {MAIN[i]: {MAIN[i + 1]} for i in range(len(MAIN) - 1)}
NEXT["RELEASE_APPROVED"] = set()
for s in MAIN[:-1]:
    NEXT[s] |= {"FAILED", "BLOCKED", "REVIEW_REQUIRED", "ABANDONED"}
NEXT["FAILED"] = {"ROLLED_BACK", "ANALYZED", "ABANDONED"}
NEXT["BLOCKED"] = {"ANALYZED", "ABANDONED", "REVIEW_REQUIRED"}
NEXT["REVIEW_REQUIRED"] = {"ANALYZED", "ABANDONED"}  # + el estado de origen (ver transition): no es un atajo hacia la verificación
NEXT["ROLLED_BACK"] = {"ANALYZED", "ABANDONED"}
NEXT["ABANDONED"] = set()

# Quién puede ENTRAR a cada estado.
ENTER = {
    "ANALYZED": {"ARCHITECT", "CRYPTO-ENGINEER", "REPAIR-ENGINEER", "ADVERSARIAL-AUDITOR"},
    "APPROVED_FOR_IMPLEMENTATION": {"ARCHITECT", "SECURITY-CHAIR", "HUMAN"},
    "IMPLEMENTED": {"IMPLEMENTER", "REPAIR-ENGINEER"},
    "TESTING": {"VERIFIER"},
    "INDEPENDENT_REVIEW": {"VERIFIER"},
    "VERIFIED": {"VERIFIER", "ADVERSARIAL-AUDITOR"},
    "RELEASE_REVIEW": {"RELEASE-GUARDIAN"},
    "RELEASE_APPROVED": {"HUMAN"},  # ningún agente aprueba una liberación
    "FAILED": {"VERIFIER", "RELEASE-GUARDIAN"},
    "BLOCKED": {"SECURITY-CHAIR", "RELEASE-GUARDIAN", "VERIFIER"},
    "REVIEW_REQUIRED": ROLES,
    "ROLLED_BACK": {"RELEASE-GUARDIAN", "HUMAN"},
    "ABANDONED": {"HUMAN", "SECURITY-CHAIR"},
}
NEEDS_INDEPENDENCE = {"INDEPENDENT_REVIEW", "VERIFIED", "RELEASE_REVIEW", "RELEASE_APPROVED"}
PROMOTING = {"VERIFIED", "RELEASE_REVIEW", "RELEASE_APPROVED"}


@dataclass
class Task:
    task_id: str
    objective: str
    module: str
    baseline_version: str
    threat_model: str
    acceptance_criteria: list[str]
    assigned_role: str
    permitted_tools: list[str]
    required_tests: list[str]
    risk_level: int  # 1 automático · 2 revisión · 3 bloqueado hasta aprobación humana
    approval_requirements: list[str]
    final_state: str = "CREATED"
    evidence_references: list[str] = field(default_factory=list)
    implementer_id: str = ""
    blocking_findings: list[str] = field(default_factory=list)
    resume_to: str = ""


class Workflow:
    def __init__(self, path: str | Path, approval_verifier: Callable[[str], bool] | None = None) -> None:
        self.log = ChainLog(path)
        # RELEASE_APPROVED exige comprobar la declaración firmada; sin verificador configurado se FALLA CERRADO.
        self._verify_approval = approval_verifier

    def _tasks(self) -> dict[str, dict]:
        self.log.verify()  # el estado se reconstruye solo desde un registro íntegro
        out: dict[str, dict] = {}
        for e in self.log.entries():
            b = json.loads(e["body"])
            if b["kind"] == "create":
                out[b["task"]["task_id"]] = b["task"]
            elif b["kind"] == "transition":
                t = out[b["task_id"]]
                t["final_state"] = b["to"]
                t["evidence_references"] = t["evidence_references"] + b.get("evidence", [])
                if b.get("implementer_id"):
                    t["implementer_id"] = b["implementer_id"]
                if b.get("add_findings"):
                    t["blocking_findings"] = sorted(set(t["blocking_findings"]) | set(b["add_findings"]))
                if b.get("clear_finding"):
                    t["blocking_findings"] = [f for f in t["blocking_findings"] if f != b["clear_finding"]]
                if b["to"] == "REVIEW_REQUIRED":
                    t["resume_to"] = b["from"]
        return out

    def create(self, task: Task) -> None:
        if task.task_id in self._tasks():
            raise QCEError("tarea duplicada")
        if task.assigned_role not in ROLES or task.risk_level not in (1, 2, 3):
            raise QCEError("rol o nivel de riesgo inválido")
        self.log.append({"kind": "create", "task": asdict(task)})

    def state(self, task_id: str) -> str:
        return self._tasks()[task_id]["final_state"]

    def get(self, task_id: str) -> dict:
        return self._tasks()[task_id]

    def transition(self, task_id: str, to: str, role: str, actor_id: str, evidence: list[str] | None = None,
                   blocking_findings: list[str] | None = None) -> None:
        t = self._tasks()[task_id]
        cur = t["final_state"]
        allowed = set(NEXT.get(cur, set()))
        if cur == "REVIEW_REQUIRED" and t.get("resume_to"):
            allowed.add(t["resume_to"])  # solo se vuelve a donde se estaba
        if to not in allowed:
            raise QCEError(f"transición no permitida {cur} → {to}")
        if role not in ENTER.get(to, set()):
            raise QCEError(f"el rol {role} no puede llevar una tarea a {to}")
        if to == "APPROVED_FOR_IMPLEMENTATION":
            if not t["acceptance_criteria"]:
                raise QCEError("faltan criterios de aceptación")
            if t["risk_level"] >= 3 and role != "HUMAN":
                raise QCEError("riesgo nivel 3: la aprobación de implementación es humana")
        implementer = t["implementer_id"]
        extra: dict = {}
        if to == "IMPLEMENTED":
            extra["implementer_id"] = actor_id
        if to in NEEDS_INDEPENDENCE and implementer and actor_id == implementer:
            raise QCEError("regla de independencia: el implementador no puede evaluar su propio cambio")
        findings = sorted(set(t["blocking_findings"]) | set(blocking_findings or []))  # solo se AÑADEN aquí
        if to in PROMOTING and findings:
            raise QCEError(f"hallazgos bloqueantes abiertos: {findings}")
        if to in ("INDEPENDENT_REVIEW", "VERIFIED") and not evidence:
            raise QCEError("se requiere evidencia (referencias a ejecuciones reales)")
        if to == "RELEASE_APPROVED":
            refs = [e[len("approval:"):] for e in (evidence or []) if e.startswith("approval:")]
            if self._verify_approval is None or not refs or not all(self._verify_approval(r) for r in refs):
                raise QCEError("falta una declaración de aprobación firmada y verificable (approval:<ref>)")
        rec = {"kind": "transition", "task_id": task_id, "from": cur, "to": to, "role": role, "actor": actor_id,
               "evidence": evidence or [], **extra}
        if blocking_findings:
            rec["add_findings"] = blocking_findings
        self.log.append(rec)

    def resolve_finding(self, task_id: str, finding: str, role: str, actor_id: str, evidence: list[str]) -> None:
        """Cerrar un hallazgo es una acción propia: otro rol distinto del implementador y con evidencia."""
        t = self._tasks()[task_id]
        if role not in ("SECURITY-CHAIR", "VERIFIER") or not evidence:
            raise QCEError("cerrar un hallazgo exige SECURITY-CHAIR/VERIFIER y evidencia")
        if actor_id == t["implementer_id"]:
            raise QCEError("el implementador no puede cerrar hallazgos de su propio cambio")
        if finding not in t["blocking_findings"]:
            raise QCEError("hallazgo inexistente")
        self.log.append({"kind": "transition", "task_id": task_id, "from": t["final_state"], "to": t["final_state"],
                         "role": role, "actor": actor_id, "evidence": evidence, "clear_finding": finding})

    def history(self, task_id: str) -> list[str]:
        return [b["to"] for b in (json.loads(e["body"]) for e in self.log.entries())
                if b.get("task_id") == task_id and not b.get("clear_finding")]
