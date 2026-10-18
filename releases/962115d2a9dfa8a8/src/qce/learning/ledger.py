"""Libro de incidentes y lecciones (memoria técnica versionada, sin secretos).

Reglas de aprendizaje:
- Una lección solo pasa a "CONFIRMED" con una prueba de regresión que FALLABA antes de la
  reparación y PASA después, más evidencia independiente del código que la generó.
- Un incidente sin reproducción es "no_confirmado" y no puede cerrarse como resuelto.
- Dos o más incidentes con la misma categoría de causa raíz disparan una propuesta estructural.
"""
from __future__ import annotations

import json
import re
import time
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path

from ..core.chainlog import ChainLog
from ..core.errors import QCEError

LESSON_STATES = ("PROPOSED", "CONFIRMED", "REJECTED", "SUPERSEDED")
CONFIDENCE = ("CONFIRMADA", "PROBABLE", "DESCONOCIDA")
STATUSES = ("abierto", "no_confirmado", "reproducido", "reparacion_propuesta", "resuelto", "bloqueado")
SEVERITIES = ("baja", "media", "alta", "critica")
TEST_REF = re.compile(r"^tests/[\w./-]+\.py(::\w+)?$")


def check_test_ref(ref: str) -> None:
    """Solo referencias de prueba bien formadas: nada de opciones de pytest ('--collect-only') ni rutas arbitrarias."""
    if not TEST_REF.match(ref) or ".." in ref:
        raise QCEError(f"referencia de prueba inválida: {ref[:60]!r}")


ROOT_CAUSES = ("codigo", "configuracion", "dependencia", "protocolo", "especificacion", "prueba_insuficiente")


@dataclass
class Incident:
    incident_id: str
    version: str
    module: str
    symptom: str
    root_cause_category: str = "desconocida"
    root_cause: str = ""
    impact: str = ""
    reproduction_test: str = ""
    repair: str = ""
    tests_run: list[str] = field(default_factory=list)
    residual_risks: list[str] = field(default_factory=list)
    lesson: str = ""
    lesson_state: str = "PROPOSED"
    confidence: str = "DESCONOCIDA"  # certeza de la causa raíz
    severity: str = "media"
    repair_level: int = 2  # 1 auto, 2 revisión, 3 bloqueado hasta autorización
    approval: str = "pendiente"
    status: str = "abierto"
    evidence: list[str] = field(default_factory=list)
    independent_evidence: bool = False


class Ledger:
    def __init__(self, path: str | Path) -> None:
        self.log = ChainLog(path)

    def _state(self) -> dict[str, dict]:
        out: dict[str, dict] = {}
        for e in self.log.entries():
            body = json.loads(e["body"])
            out.setdefault(body["incident_id"], {}).update(body)
        return out

    def open(self, inc: Incident) -> str:
        if inc.incident_id in self._state():
            raise QCEError("incidente duplicado")
        # Un incidente NACE sin resolver, sin lección confirmada y sin causa confirmada por decreto (hallazgo 7).
        if inc.status not in ("abierto", "no_confirmado", "reproducido") or inc.lesson_state != "PROPOSED" \
                or inc.confidence == "CONFIRMADA":
            raise QCEError("estado inicial inválido: resolver/confirmar exige actualizaciones con evidencia")
        if inc.severity not in SEVERITIES:
            raise QCEError("severidad inválida")
        if inc.reproduction_test:
            check_test_ref(inc.reproduction_test)
        if inc.root_cause_category not in ROOT_CAUSES + ("desconocida",):
            raise QCEError("categoría de causa raíz inválida")
        self.log.append({**asdict(inc), "date": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})
        return inc.incident_id

    def update(self, incident_id: str, **changes) -> None:
        cur = self._state().get(incident_id)
        if cur is None:
            raise QCEError("incidente inexistente")
        if changes.get("reproduction_test"):
            check_test_ref(changes["reproduction_test"])
        if changes.get("status") == "resuelto":
            if not (cur.get("reproduction_test") or changes.get("reproduction_test")):
                raise QCEError("no se puede resolver sin una prueba de reproducción")
            if not (cur.get("tests_run") or changes.get("tests_run")):
                raise QCEError("no se puede resolver sin resultados de pruebas")
        if "lesson_state" in changes and changes["lesson_state"] not in LESSON_STATES:
            raise QCEError("estado de lección inválido")
        if "confidence" in changes and changes["confidence"] not in CONFIDENCE:
            raise QCEError("nivel de certeza inválido")
        if changes.get("confidence") == "CONFIRMADA" and not (cur.get("reproduction_test") or changes.get("reproduction_test")):
            raise QCEError("causa CONFIRMADA requiere reproducción")
        if changes.get("lesson_state") == "CONFIRMED":
            merged = {**cur, **changes}
            if not merged.get("reproduction_test") or not merged.get("independent_evidence"):
                raise QCEError("lección confirmada requiere prueba de regresión y evidencia independiente")
        if changes.get("approval") == "aprobado" and cur.get("repair_level", 2) >= 3 and "approver" not in changes:
            raise QCEError("nivel 3 requiere aprobador humano identificado")
        self.log.append({"incident_id": incident_id, **changes})

    def get(self, incident_id: str) -> dict:
        return self._state()[incident_id]

    def all(self) -> list[dict]:
        return list(self._state().values())

    def next_id(self) -> str:
        return f"INC-{len(self._state()) + 1:04d}"

    def patterns(self) -> list[str]:
        """Causas raíz repetidas → propuesta de cambio estructural."""
        c = Counter(i.get("root_cause_category") for i in self.all()
                    if i.get("root_cause_category") not in (None, "desconocida"))
        return [f"{n} incidentes con causa '{cat}': revisar el diseño, no solo el síntoma"
                for cat, n in c.items() if n >= 2]

    def open_blockers(self) -> list[str]:
        return [i["incident_id"] for i in self.all()
                if i.get("severity") in ("critica", "alta") and i.get("status") != "resuelto"]
