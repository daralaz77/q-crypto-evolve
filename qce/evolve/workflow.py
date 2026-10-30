"""Máquina de estados del cambio (v3) con registro estructurado de tarea y reglas de independencia.

Cada transición se anexa a una cadena de hashes (learning/tasks.jsonl). El estado actual se
reconstruye SIEMPRE desde el registro: no hay estado en memoria que un agente pueda alterar.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable

import re

from ..core.chainlog import ChainLog
from ..core.errors import QCEError
from ..pqc.hybrid import hybrid_verify

ID_OK = re.compile(r"^(?![0-9a-fA-F]{32,}$)[A-Za-z0-9._-]{1,40}$")
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


def _norm(actor: str) -> str:
    """Identidad comparable: sin espacios, unicode normalizado y sin distinguir mayúsculas (hallazgo B2)."""
    import unicodedata
    return unicodedata.normalize("NFKC", actor).strip().casefold()


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
    implementer_ids: list[str] = field(default_factory=list)


CTX_TRANSITION = b"QCE1/workflow-transition"


def transition_payload(head: str, task_id: str, cur: str, to: str, role: str, actor_id: str, evidence: list[str] | None,
                       blocking_findings: list[str] | None) -> bytes:
    """Bytes que firma el actor: ligan la transición al ESTADO EXACTO del registro (`head`) y a la tarea, así una firma no se puede reutilizar en otra transición ni repetir."""
    body = json.dumps({"head": head, "task": task_id, "from": cur, "to": to, "role": role, "actor": actor_id,
                       "evidence": list(evidence or []), "findings": sorted(blocking_findings or [])}, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(body.encode()).digest()


class Workflow:
    def __init__(self, path: str | Path, approval_verifier: Callable[[str], bool] | None = None,
                 actor_keys: Callable[[str], bytes | None] | None = None) -> None:
        self.log = ChainLog(path)
        # Con `actor_keys` (actor_id → clave pública híbrida registrada o None), CADA transición exige la firma del actor; sin él, el comportamiento histórico
        # (los actor_id se afirman, no se autentican: ver LIMITATIONS.md).
        self._actor_keys = actor_keys
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
                    t["implementer_ids"] = sorted(set(t["implementer_ids"]) | {_norm(b["implementer_id"])})  # todo autor, nunca solo el último
                if b.get("add_findings"):
                    t["blocking_findings"] = sorted(set(t["blocking_findings"]) | set(b["add_findings"]))
                if b.get("clear_finding"):
                    t["blocking_findings"] = [f for f in t["blocking_findings"] if f != b["clear_finding"]]
                if b["to"] == "REVIEW_REQUIRED":
                    t["resume_to"] = b["from"]
        return out

    def create(self, task: Task) -> None:
        if not ID_OK.match(task.task_id):
            raise QCEError("task_id inválido (1-40 caracteres seguros y no un hex largo, que el redactor confundiría con un secreto)")
        if task.task_id in self._tasks():
            raise QCEError("tarea duplicada")
        if task.assigned_role not in ROLES or task.risk_level not in (1, 2, 3):
            raise QCEError("rol o nivel de riesgo inválido")
        # El estado inicial NO lo decide quien crea la tarea (hallazgo A4): siempre CREATED y sin historial heredado.
        clean = asdict(task) | {"final_state": "CREATED", "evidence_references": [], "implementer_id": "", "implementer_ids": [],
                                "blocking_findings": [], "resume_to": ""}
        self.log.append({"kind": "create", "task": clean})

    def state(self, task_id: str) -> str:
        return self._tasks()[task_id]["final_state"]

    def get(self, task_id: str) -> dict:
        return self._tasks()[task_id]

    def signing_payload(self, task_id: str, to: str, role: str, actor_id: str, evidence: list[str] | None = None,
                        blocking_findings: list[str] | None = None) -> bytes:
        """Lo que el actor debe firmar (con CTX_TRANSITION) para esta transición, sobre el estado ACTUAL del registro."""
        return transition_payload(self.log.head(), task_id, self._tasks()[task_id]["final_state"], to, role, actor_id, evidence, blocking_findings)

    def transition(self, task_id: str, to: str, role: str, actor_id: str, evidence: list[str] | None = None,
                   blocking_findings: list[str] | None = None, signature: bytes | None = None) -> None:
        head = self.log.head()  # todo lo validado se refiere a ESTE estado del registro
        t = self._tasks()[task_id]
        cur = t["final_state"]
        if self._actor_keys is not None:
            pub = self._actor_keys(actor_id)
            if pub is None or not signature:
                raise QCEError("transición sin firma de un actor registrado")
            try:
                hybrid_verify(pub, transition_payload(head, task_id, cur, to, role, actor_id, evidence, blocking_findings), signature, CTX_TRANSITION)
            except Exception as exc:  # noqa: BLE001  (cualquier fallo de verificación = rechazo; no se filtra el motivo)
                raise QCEError("firma de la transición inválida") from exc
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
        implementers = set(t["implementer_ids"]) | ({_norm(t["implementer_id"])} if t["implementer_id"] else set())
        extra: dict = {}
        if to == "IMPLEMENTED":
            extra["implementer_id"] = actor_id
        if to in NEEDS_INDEPENDENCE and _norm(actor_id) in implementers:
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
        if self._actor_keys is not None:
            rec["signed"] = True
        if blocking_findings:
            if not all(isinstance(f, str) and ID_OK.match(f) for f in blocking_findings):
                raise QCEError("identificador de hallazgo inválido")
            rec["add_findings"] = blocking_findings
        self.log.append(rec, expected_head=head)

    def resolve_finding(self, task_id: str, finding: str, role: str, actor_id: str, evidence: list[str]) -> None:
        """Cerrar un hallazgo es una acción propia: otro rol distinto del implementador y con evidencia."""
        head = self.log.head()
        t = self._tasks()[task_id]
        if role not in ("SECURITY-CHAIR", "VERIFIER") or not evidence:
            raise QCEError("cerrar un hallazgo exige SECURITY-CHAIR/VERIFIER y evidencia")
        if _norm(actor_id) in set(t["implementer_ids"]) | {_norm(t["implementer_id"])}:
            raise QCEError("el implementador no puede cerrar hallazgos de su propio cambio")
        if finding not in t["blocking_findings"]:
            raise QCEError("hallazgo inexistente")
        self.log.append({"kind": "transition", "task_id": task_id, "from": t["final_state"], "to": t["final_state"],
                         "role": role, "actor": actor_id, "evidence": evidence, "clear_finding": finding},
                        expected_head=head)

    def history(self, task_id: str) -> list[str]:
        return [b["to"] for b in (json.loads(e["body"]) for e in self.log.entries())
                if b.get("task_id") == task_id and not b.get("clear_finding")]
