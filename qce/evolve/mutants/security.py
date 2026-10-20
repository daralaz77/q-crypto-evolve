"""Mutantes de security (7). Archivos que rompen: qce/security/approvals.py, qce/security/scanners.py."""
from ._base import Mutant as M

MUTANTS = [
    M("scan-fromimport-off", "qce/security/scanners.py", (("if node.module == \"random\":", "if False:"),), "escáner from-import"),
    M("trust-key-unique-off", "qce/security/approvals.py", (("if e[\"public_key\"] == public_bytes.hex() and other != identity:", "if False:"),), "una clave = una identidad"),
    M("trust-veto-off", "qce/security/approvals.py", (("if not reg_p.exists() or has_valid_veto(root, release_id, role):", "if not reg_p.exists():"),), "veto de reject"),
    M("appr-casefold-off", "qce/security/approvals.py", (('if other != identity and unicodedata.normalize("NFKC", other).casefold() == identity.casefold():', 'if False:'),), "identidades sin colisión"),
    M("appr-role-change-off", "qce/security/approvals.py", (('if identity in data and data[identity]["role"] != role:', 'if False:'),), "sin cambio de rol"),
    M("appr-filename-verdict-off", "qce/security/approvals.py", (('[:16]}.{verdict}.json"', '[:16]}.json"'),), "accept no pisa reject"),
    M("appr-junk-off", "qce/security/approvals.py", (('except (ValueError, OSError, AttributeError):', 'except OSError:'),), "ficheros basura"),
]
