"""Máquina de estados del cambio (v3) con registro estructurado de tarea y reglas de independencia.

Cada transición se anexa a una cadena de hashes (learning/tasks.jsonl). El estado actual se
reconstruye SIEMPRE desde el registro: no hay estado en memoria que un agente pueda alterar.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

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
NEXT["REVIEW_REQUIRED"] = {"INDEPENDENT_REVIEW", "ANALYZED", "ABANDONED"}
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


class Workflow:
    def __init__(self, path: str | Path) -> None:
        self.log = ChainLog(path)

    def _tasks(self) -> dict[str, dict]:
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
                if "blocking_findings" in b:
                    t["blocking_findings"] = b["blocking_findings"]
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
        if to not in NEXT.get(cur, set()):
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
        findings = blocking_findings if blocking_findings is not None else t["blocking_findings"]
        if to in PROMOTING and findings:
            raise QCEError(f"hallazgos bloqueantes abiertos: {findings}")
        if to in ("INDEPENDENT_REVIEW", "VERIFIED") and not evidence:
            raise QCEError("se requiere evidencia (referencias a ejecuciones reales)")
        if to == "RELEASE_APPROVED" and t["risk_level"] >= 2 and not any(e.startswith("approval:") for e in (evidence or [])):
            raise QCEError("falta referencia a la declaración de aprobación firmada (approval:<archivo>)")
        rec = {"kind": "transition", "task_id": task_id, "from": cur, "to": to, "role": role, "actor": actor_id,
               "evidence": evidence or [], **extra}
        if blocking_findings is not None:
            rec["blocking_findings"] = blocking_findings
        self.log.append(rec)

    def history(self, task_id: str) -> list[str]:
        return [json.loads(e["body"])["to"] for e in self.log.entries()
                if json.loads(e["body"]).get("task_id") == task_id]
