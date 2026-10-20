"""Demostración EJECUTADA del ciclo: fallo controlado → detección → incidente → reparación aislada →
revisión independiente → regresión al reintroducir → bloqueo → reversión → persistencia.

Todo ocurre en una copia de laboratorio (directorio temporal). El proyecto real no se modifica
y ninguna clave real interviene (las claves de firma de la demo son efímeras, solo en memoria).
Cada comprobación sale de una observación real (códigos de salida, hashes, estados), no de afirmaciones.
"""
from __future__ import annotations

import difflib
import json
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from ..core.errors import QCEError
from ..key_management import vault
from ..key_management.keystore import KeyStore, Purpose
from ..learning.ledger import Incident, Ledger
from ..pqc.hybrid import HybridSigPrivateKey
from ..recovery import release as rel
from ..security import approvals
from . import gates
from .mutation import MUTANTS
from .workflow import Task, Workflow

FAULT = next(m for m in MUTANTS if m.name == "hs-server-sig-not-verified")
IMPL, REV, HUMAN = "agente-impl", "agente-rev", "humano-lab"


def _pytest(root: Path, *args: str) -> tuple[int, str]:
    r = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-x", *args], cwd=root,
                       capture_output=True, text=True, env={"PYTHONPATH": str(root), "PATH": "/usr/bin:/bin"})
    return r.returncode, r.stdout + r.stderr


def _apply(path: Path, edits, reverse=False) -> None:
    s = path.read_text()
    for old, new in edits:
        a, b = (new, old) if reverse else (old, new)
        if s.count(a) != 1:
            raise RuntimeError("fragmento no encontrado en la copia de laboratorio")
        s = s.replace(a, b)
    path.write_text(s)


def run(project: Path, out_dir: Path) -> dict:
    checks: list[dict] = []
    log: list[str] = []

    def check(name: str, ok: bool, observed: str) -> None:
        checks.append({"check": name, "ok": bool(ok), "observed": observed})
        log.append(f"[{'OK ' if ok else 'FALLA'}] {name} — {observed}")

    t_start = time.time()
    with tempfile.TemporaryDirectory(prefix="qce-lab-") as td:
        lab = Path(td) / "lab"
        shutil.copytree(project, lab, ignore=shutil.ignore_patterns(
            ".venv", "__pycache__", ".git", "releases", "reviews", ".hypothesis", "benchmarks", "trust"))
        sess = lab / "qce" / "protocols" / "session.py"
        ledger = Ledger(lab / "learning" / "incidents.jsonl")
        wf = Workflow(lab / "learning" / "tasks.jsonl")
        keys = {n: HybridSigPrivateKey.generate() for n in (IMPL, REV, HUMAN)}  # efímeras, solo en memoria
        approvals.register(lab, "implementer", IMPL, keys[IMPL].public_bytes)
        approvals.register(lab, "reviewer", REV, keys[REV].public_bytes)
        approvals.register(lab, "approver", HUMAN, keys[HUMAN].public_bytes)

        # ---- 1. línea base confiable ---------------------------------------------------------------
        rc, out = _pytest(lab)
        check("1. línea base: toda la batería pasa", rc == 0, out.strip().splitlines()[-1])
        m0 = rel.build_manifest(lab, "lab-0", {"pytest": "pass"}, [], {})
        rel.save_release(lab, m0)
        approvals.sign_statement(lab, keys[HUMAN], "approver", HUMAN, m0["release_id"], "accept")  # firma humana (clave efímera de la demo)
        rel.mark_stable(lab, m0["release_id"], HUMAN)
        r0 = m0["release_id"]
        wf.create(Task("T-LAB-1", "demostrar el ciclo de reparación", "qce.protocols.session", "lab-0", "TM: suplantación del servidor",
                       ["los tests de autenticación del servidor pasan", "ningún control debilitado"], "IMPLEMENTER",
                       ["pytest"], ["tests/test_session.py"], 2, ["reviewer independiente"]))
        wf.transition("T-LAB-1", "ANALYZED", "ARCHITECT", "arq-1")
        wf.transition("T-LAB-1", "APPROVED_FOR_IMPLEMENTATION", "ARCHITECT", "arq-1")
        wf.transition("T-LAB-1", "IMPLEMENTED", "IMPLEMENTER", IMPL)  # "implementa" el cambio defectuoso:

        # ---- 2. fallo controlado --------------------------------------------------------------------
        _apply(sess, FAULT.edits)
        wf.transition("T-LAB-1", "TESTING", "VERIFIER", "ver-1")

        # ---- 3. detección ------------------------------------------------------------------------------
        t_detect = time.time()
        rc, out = _pytest(lab)
        failing = [ln.split(" ")[1] if ln.startswith("FAILED") else ln for ln in out.splitlines() if ln.startswith("FAILED")]
        check("2. el fallo controlado es detectado por las pruebas", rc != 0 and bool(failing), f"falla: {failing[:2]}")
        cat, hint = rel.classify_failure(out)
        repro = failing[0].split(" - ")[0] if failing else ""
        diff = [f for f in m0["files"] if hashlib_file(lab / f) != m0["files"][f]]
        check("3. aislamiento de causa: un único archivo difiere de la versión estable", diff == ["qce/protocols/session.py"], f"difiere: {diff}")
        level = rel.change_level(diff)
        check("4. el cambio se clasifica como nivel 2 (protocolo → revisión obligatoria)", level == 2, f"nivel {level}")
        inc_id = ledger.next_id()
        ledger.open(Incident(inc_id, "lab-0", "qce.protocols.session", "el cliente acepta un servidor suplantado (firma no verificada)",
                             root_cause_category="codigo" if cat == "desconocida" else cat, severity="critica",
                             reproduction_test=repro, repair_level=level, status="reproducido",
                             evidence=[f"pytest exit={rc}", f"clasificador: {cat} ({hint})"]))
        ledger.update(inc_id, confidence="CONFIRMADA",
                      root_cause="la llamada hybrid_verify del cliente fue eliminada (diferencia verificada contra el snapshot estable)")
        t_to_incident = round(time.time() - t_detect, 2)
        wf.transition("T-LAB-1", "FAILED", "VERIFIER", "ver-1", [f"pytest:{repro}"])

        # ---- 4. puerta bloquea la promoción -------------------------------------------------------
        rep = gates.evaluate(lab, version="lab-bad", run_mutation=False, run_dep_audit=False)
        st = {g["gate"][:2]: g["status"] for g in rep["gates"]}
        check("5. el candidato defectuoso NO se promueve (BLOCKED/FAILED, G2 en fallo)", rep["state"] in ("BLOCKED", "FAILED") and st["G2"] == "fail",
              f"estado={rep['state']} G2={st['G2']} G3={st['G3']}")
        check("6. sin evidencia (mutación/dependencias no ejecutadas) la puerta de seguridad bloquea", st["G3"] == "blocked",
              next(g["detail"] for g in rep["gates"] if g["gate"].startswith("G3"))[:110])

        # ---- 5. reparación mínima aislada ------------------------------------------------------------
        t_rep = time.time()
        stable_src = (lab / "releases" / r0 / "src" / "qce/protocols/session.py").read_text()
        patch = "".join(difflib.unified_diff(sess.read_text().splitlines(True), stable_src.splitlines(True), "fallo", "reparado"))
        _apply(sess, FAULT.edits, reverse=True)  # parche mínimo = deshacer la eliminación del control
        (lab / "tests" / "test_lab_regression.py").write_text(
            f'"""Regresión de {inc_id}: el cliente debe rechazar a un servidor con otra identidad."""\n'
            "import pytest\nfrom qce.core.errors import AuthenticationFailure\nfrom qce.pqc.hybrid import HybridSigPrivateKey\n"
            "from qce.protocols.session import ClientHandshake, ServerHandshake\n\n\n"
            f"def test_{inc_id.lower().replace('-', '_')}_impostor_server_rejected():\n"
            "    real, impostor = HybridSigPrivateKey.generate(), HybridSigPrivateKey.generate()\n"
            "    c, s = ClientHandshake(real.public_bytes), ServerHandshake(impostor)\n"
            "    with pytest.raises(AuthenticationFailure):\n        c.on_server_hello(s.on_client_hello(c.start()))\n")
        new_test = f"tests/test_lab_regression.py::test_{inc_id.lower().replace('-', '_')}_impostor_server_rejected"
        rc_after, out_after = _pytest(lab)
        check("7. tras la reparación toda la batería vuelve a pasar", rc_after == 0, out_after.strip().splitlines()[-1])
        check("8. el parche es mínimo (≈1 línea cambiada)", 0 < sum(1 for l in patch.splitlines() if l.startswith(("+", "-")) and not l.startswith(("+++", "---"))) <= 2,
              f"{sum(1 for l in patch.splitlines() if l.startswith(('+', '-')) and not l.startswith(('+++', '---')))} líneas +/-")
        ledger.update(inc_id, status="resuelto", reproduction_test=new_test, repair="restaurar hybrid_verify en ClientHandshake.on_server_hello",
                      tests_run=[f"pytest completo exit={rc_after}"], approval="pendiente_revision_humana",
                      residual_risks=["la demo corrige un fallo conocido por construcción; no prueba hallazgo de fallos desconocidos"],
                      lesson="Toda ruta de autenticación necesita una prueba negativa con identidad falsa", lesson_state="PROPOSED")
        t_repair = round(time.time() - t_rep, 2)
        wf.transition("T-LAB-1", "ANALYZED", "REPAIR-ENGINEER", "rep-1")
        wf.transition("T-LAB-1", "APPROVED_FOR_IMPLEMENTATION", "ARCHITECT", "arq-1")
        wf.transition("T-LAB-1", "IMPLEMENTED", "REPAIR-ENGINEER", "rep-1")
        wf.transition("T-LAB-1", "TESTING", "VERIFIER", "ver-1")

        # ---- 6. independencia + autorización --------------------------------------------------------------
        r1 = rel.build_manifest(lab, "lab-1", {}, [], {})["release_id"]
        check("9. el código cambió, así que las firmas de la versión anterior NO valen", r1 != r0 and approvals.valid_statements(lab, r1, "reviewer") == [], f"{r0} → {r1}")
        approvals.sign_statement(lab, keys[IMPL], "implementer", IMPL, r1, "accept")
        approvals.sign_statement(lab, keys[IMPL], "reviewer", REV, r1, "accept")  # el implementador se hace pasar por revisor
        rep = gates.evaluate(lab, version="lab-1", run_mutation=False, run_dep_audit=False)
        g5 = next(g for g in rep["gates"] if g["gate"].startswith("G5"))
        check("10. autorrevisión / firma suplantada del revisor es rechazada (G5 no pasa)", g5["status"] != "pass", g5["detail"])
        approvals.sign_statement(lab, keys[REV], "reviewer", REV, r1, "accept")  # firma legítima sobrescribe
        rep = gates.evaluate(lab, version="lab-1", run_mutation=False, run_dep_audit=False)
        g5 = next(g for g in rep["gates"] if g["gate"].startswith("G5"))
        check("11. revisión firmada por un agente distinto: G5 pasa", g5["status"] == "pass", g5["detail"])
        check("12. aun así NO es RELEASE_APPROVED (falta autorización humana y evidencia completa)", rep["state"] != "RELEASE_APPROVED", f"estado={rep['state']}")
        wf.transition("T-LAB-1", "INDEPENDENT_REVIEW", "VERIFIER", "ver-1", ["run:pytest-lab-1"])
        try:
            wf.transition("T-LAB-1", "VERIFIED", "VERIFIER", "rep-1", ["run:x"])  # rep-1 implementó la reparación
            ok = False
        except QCEError:
            ok = True
        check("13. el implementador no puede marcar su propio cambio como VERIFIED", ok, "QCEError (regla de independencia)")
        wf.transition("T-LAB-1", "VERIFIED", "VERIFIER", "ver-1", ["run:pytest-lab-1"])

        # ---- 7. el estado criptográfico real no se debe tocar al revertir -------------------------------
        ks = KeyStore()
        kid = ks.create(Purpose.ENCRYPT, 3600)
        ks.activate(kid)
        ks.revoke(kid, "compromiso simulado")
        vault.save(ks, lab / "vault.bin", "frase-de-laboratorio", n=2**14)
        vault_before = hashlib_file(lab / "vault.bin")
        ledger_head_before = ledger.log.head()

        # ---- 8. regresión: se reintroduce el fallo -----------------------------------------------------------
        _apply(sess, FAULT.edits)
        rep = gates.evaluate(lab, version="lab-2-reintroduced", run_mutation=False, run_dep_audit=False)
        g4 = next(g for g in rep["gates"] if g["gate"].startswith("G4"))
        check("14. al reintroducir el fallo, la prueba histórica lo detecta (G4 REGRESIÓN)", g4["status"] == "fail" and inc_id in g4["evidence"].get("regressed", []), g4["detail"])
        check("15. la versión con regresión no se promueve", rep["state"] in ("FAILED", "BLOCKED"), f"estado={rep['state']}")

        # ---- 9. reversión segura ------------------------------------------------------------------------------
        t_rb = time.time()
        wf.transition("T-LAB-1", "RELEASE_REVIEW", "RELEASE-GUARDIAN", "rg-1")
        restored = rel.rollback(lab)
        t_recover = round(time.time() - t_rb, 2)
        check("16. la reversión restaura el código exactamente (hash = snapshot estable)", hashlib_file(sess) == m0["files"]["qce/protocols/session.py"], f"restaurados {len(restored)} archivos")
        rc, out = _pytest(lab)
        check("17. tras revertir, las pruebas críticas vuelven a pasar", rc == 0, out.strip().splitlines()[-1])
        check("18. la reversión NO tocó el vault ni el libro de incidentes", hashlib_file(lab / "vault.bin") == vault_before and ledger.log.head() == ledger_head_before, "vault y cadena de evidencia intactos")
        check("19. la clave revocada sigue revocada tras revertir el código", vault.load(lab / "vault.bin", "frase-de-laboratorio").info(kid).state.value == "REVOKED", "estado=REVOKED")

        # ---- 10. controles no debilitados ----------------------------------------------------------------------
        gj = lab / "gates.json"
        orig = gj.read_text()
        cfg = json.loads(orig)
        cfg["min_mutation_score"] = 0.5
        gj.write_text(json.dumps(cfg))
        rep = gates.evaluate(lab, version="lab-weakened", run_mutation=False, run_dep_audit=False)
        g1 = next(g for g in rep["gates"] if g["gate"].startswith("G1"))
        check("20. intentar aflojar los criterios de aceptación bloquea (trinquete G1)", g1["status"] == "blocked" and "debilitado" in g1["detail"], g1["detail"][:100])
        gj.write_text(orig)
        check("21. el nivel de un cambio a gates.json es 3 (bloqueado hasta aprobación humana)", rel.change_level(["gates.json"]) == 3, "nivel 3")

        # ---- 11. persistencia entre sesiones -----------------------------------------------------------------------
        L2, W2 = Ledger(lab / "learning" / "incidents.jsonl"), Workflow(lab / "learning" / "tasks.jsonl")
        again = L2.get(inc_id)
        rep = gates.evaluate(lab, version="lab-3-next-session", run_mutation=False, run_dep_audit=False)
        g4 = next(g for g in rep["gates"] if g["gate"].startswith("G4"))
        check("22. nueva sesión: incidente y lección recuperados desde disco", again["status"] == "resuelto" and again["lesson_state"] == "PROPOSED", f"{inc_id}: {again['status']} / lección {again['lesson_state']}")
        check("23. nueva sesión: las pruebas históricas se reutilizan automáticamente (G4)", g4["status"] == "pass" and g4["evidence"]["checked"] >= 2, g4["detail"])
        check("24. la cadena de incidentes y de tareas sigue íntegra", L2.log.verify() > 0 and W2.log.verify() > 0, f"{L2.log.verify()} + {W2.log.verify()} entradas")
        wf.transition("T-LAB-1", "FAILED", "RELEASE-GUARDIAN", "rg-1", ["g4:regression"])
        wf.transition("T-LAB-1", "ROLLED_BACK", "RELEASE-GUARDIAN", "rg-1")
        check("25. la tarea queda en ROLLED_BACK (nunca RELEASE_APPROVED sin humano)", wf.state("T-LAB-1") == "ROLLED_BACK", " → ".join(wf.history("T-LAB-1")))

    result = {
        "demo": "q-crypto-evolve lab", "all_ok": all(c["ok"] for c in checks), "checks": checks,
        "timings_s": {"deteccion_a_incidente": t_to_incident, "preparar_reparacion": t_repair, "reversion": t_recover,
                      "total": round(time.time() - t_start, 1)},
        "not_demonstrated": ["hallazgo autónomo de fallos desconocidos", "auditoría externa", "resistencia a canales laterales",
                             "hardware QKD real", "despliegue en producción"],
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "demo_latest.json").write_text(json.dumps(result, indent=2, ensure_ascii=False))
    result["log"] = log
    return result


def hashlib_file(p: Path) -> str:
    import hashlib
    return hashlib.sha256(p.read_bytes()).hexdigest()
