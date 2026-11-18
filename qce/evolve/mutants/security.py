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
    M("appr-seq-not-in-message", "qce/security/approvals.py", (("    if sequence is not None:\n        parts.append(sequence)", "    if False:\n        parts.append(sequence)"),), "la secuencia va dentro de la firma"),
    M("appr-seq-bool-accepted", "qce/security/approvals.py", (("return type(sequence) is int and", "return isinstance(sequence, int) and"),), "True no es una secuencia"),
    M("appr-seq-zero-accepted", "qce/security/approvals.py", (("and 1 <= sequence < 2**31", "and 0 <= sequence < 2**31"),), "secuencia desde 1"),
    M("appr-seq-upper-bound-inclusive", "qce/security/approvals.py", (("1 <= sequence < 2**31", "1 <= sequence <= 2**31"),), "secuencia acotada"),
    M("appr-seq-any-role", "qce/security/approvals.py", (('(role != "approver" or verdict != "accept" or not _valid_sequence(sequence))', '(verdict != "accept" or not _valid_sequence(sequence))'),), "solo el aprobador firma secuencia"),
    M("appr-seq-on-reject", "qce/security/approvals.py", (('(role != "approver" or verdict != "accept" or not _valid_sequence(sequence))', '(role != "approver" or not _valid_sequence(sequence))'),), "solo un accept lleva secuencia"),
    M("appr-seq-invalid-signed", "qce/security/approvals.py", (('(role != "approver" or verdict != "accept" or not _valid_sequence(sequence))', '(role != "approver" or verdict != "accept")'),), "no se firma una secuencia inválida"),
    M("appr-seq-dropped-on-write", "qce/security/approvals.py", (('    if sequence is not None:\n        body["sequence"] = sequence', '    if False:\n        body["sequence"] = sequence'),), "la declaración guarda la secuencia"),
    M("appr-seq-ignored-on-verify", "qce/security/approvals.py", (('_msg(role, s["signer"], release_id, "accept", seq)', '_msg(role, s["signer"], release_id, "accept")'),), "se verifica con la secuencia"),
    M("appr-seq-lost-in-result", "qce/security/approvals.py", (('        out[s["signer"]] = seq', '        out[s["signer"]] = None'),), "se devuelve la secuencia firmada"),
    M("appr-seq-wrong-role", "qce/security/approvals.py", (('return _accepted(root, release_id, "approver").get(approver)', 'return _accepted(root, release_id, "reviewer").get(approver)'),), "la secuencia es del aprobador"),
]
