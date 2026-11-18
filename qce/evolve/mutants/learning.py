"""Mutantes de learning (17). Archivos que rompen: qce/learning/ledger.py."""
from ._base import Mutant as M

MUTANTS = [
    M("ledger-open-validate-off", "qce/learning/ledger.py", (("or inc.confidence == \"CONFIRMADA\":", "or False:"),), "incidente no nace confirmado"),
    M("ledger-testref-off", "qce/learning/ledger.py", (("if not TEST_REF.match(ref) or \"..\" in ref:", "if False:"),), "sin inyección de pytest"),
    M("ledger-clear-test-off", "qce/learning/ledger.py", (('if not changes["reproduction_test"]:', 'if False:'),), "no vaciar prueba"),
    M("ledger-severity-lower-off", "qce/learning/ledger.py", (('if SEVERITIES.index(changes["severity"]) < SEVERITIES.index(cur.get("severity", "media")) and not changes.get("approver"):', 'if False:'),), "no rebajar severidad"),
    M('ledger-level-lower-off', 'qce/learning/ledger.py', (('if changes["repair_level"] < cur.get("repair_level", 2) and not changes.get("approver"):', 'if False:'),), 'no bajar el nivel de reparación sin aprobador'),
    M('ledger-level-lower-equal-blocked', 'qce/learning/ledger.py', (('changes["repair_level"] < cur.get("repair_level", 2)', 'changes["repair_level"] <= cur.get("repair_level", 2)'),), 'mantener el nivel no exige aprobador'),
    M('ledger-level-lower-empty-approver', 'qce/learning/ledger.py', (('changes["repair_level"] < cur.get("repair_level", 2) and not changes.get("approver")', 'changes["repair_level"] < cur.get("repair_level", 2) and "approver" not in changes'),), 'un aprobador vacío no cuenta (nivel)'),
    M('ledger-level-update-invalid-off', 'qce/learning/ledger.py', (('if not _valid_level(changes["repair_level"]):', 'if False:'),), 'nivel de reparación válido al actualizar'),
    M('ledger-level-open-invalid-off', 'qce/learning/ledger.py', (('if not _valid_level(inc.repair_level):', 'if False:'),), 'nivel de reparación válido al abrir'),
    M('ledger-level-bool-accepted', 'qce/learning/ledger.py', (('type(level) is int and', 'isinstance(level, int) and'),), 'True no es un nivel'),
    M('ledger-level-upper-bound', 'qce/learning/ledger.py', (('1 <= level <= 3', '1 <= level <= 4'),), 'el nivel máximo es 3'),
    M('ledger-level-lower-bound', 'qce/learning/ledger.py', (('1 <= level <= 3', '0 <= level <= 3'),), 'el nivel mínimo es 1'),
    M('ledger-level3-ignores-new-level', 'qce/learning/ledger.py', (('changes.get("repair_level", cur.get("repair_level", 2)) >= 3', 'cur.get("repair_level", 2) >= 3'),), 'subir a 3 y aprobar a la vez exige aprobador'),
    M('ledger-level3-empty-approver', 'qce/learning/ledger.py', (('>= 3 and not changes.get("approver"):', '>= 3 and "approver" not in changes:'),), 'un aprobador vacío no cuenta (nivel 3)'),
    M('ledger-severity-empty-approver', 'qce/learning/ledger.py', (('cur.get("severity", "media")) and not changes.get("approver"):', 'cur.get("severity", "media")) and "approver" not in changes:'),), 'un aprobador vacío no cuenta (severidad)'),
    M('ledger-status-invalid-off', 'qce/learning/ledger.py', (('if "status" in changes and changes["status"] not in STATUSES:', 'if False:'),), 'estado de incidente existente'),
    M('ledger-rootcause-update-invalid-off', 'qce/learning/ledger.py', (('if "root_cause_category" in changes and changes["root_cause_category"] not in ROOT_CAUSES + ("desconocida",):', 'if False:'),), 'categoría de causa existente al actualizar'),
]
