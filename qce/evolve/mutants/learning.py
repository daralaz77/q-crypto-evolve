"""Mutantes de learning (4). Archivos que rompen: qce/learning/ledger.py."""
from ._base import Mutant as M

MUTANTS = [
    M("ledger-open-validate-off", "qce/learning/ledger.py", (("or inc.confidence == \"CONFIRMADA\":", "or False:"),), "incidente no nace confirmado"),
    M("ledger-testref-off", "qce/learning/ledger.py", (("if not TEST_REF.match(ref) or \"..\" in ref:", "if False:"),), "sin inyección de pytest"),
    M("ledger-clear-test-off", "qce/learning/ledger.py", (('if not changes["reproduction_test"]:', 'if False:'),), "no vaciar prueba"),
    M("ledger-severity-lower-off", "qce/learning/ledger.py", (('if SEVERITIES.index(changes["severity"]) < SEVERITIES.index(cur.get("severity", "media")) and "approver" not in changes:', 'if False:'),), "no rebajar severidad"),
]
