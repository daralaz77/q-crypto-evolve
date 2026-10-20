"""Mutantes de security (1). Archivos que rompen: qce/security/scanners.py."""
from ._base import Mutant as M

MUTANTS = [
    M("scan-fromimport-off", "qce/security/scanners.py", (("if node.module == \"random\":", "if False:"),), "escáner from-import"),
]
