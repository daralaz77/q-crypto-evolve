"""Mutantes de recovery (7). Archivos que rompen: qce/recovery/release.py."""
from ._base import Mutant as M

MUTANTS = [
    M("rel-path-check-off", "qce/recovery/release.py", (("if os.path.isabs(rel_path) or rel_path != os.path.normpath(rel_path) or rel_path.startswith(\"..\"):", "if False:"),), "rutas del manifiesto",
      "defensa en profundidad: la comprobación resolve() posterior y el hash del snapshot rechazan las mismas rutas; ninguna variante maliciosa llega a escribir"),
    M("rel-rollback-scope-off", "qce/recovery/release.py", (("if rel.startswith(ROLLBACK_ALLOWED):  # sin symlinks ni '..' (comprobado arriba) el destino real == rel", "if True:  # sin symlinks ni '..' (comprobado arriba) el destino real == rel"),), "la reversión no toca evidencia/umbrales"),
    M("rel-stable-signature-off", "qce/recovery/release.py", (("if not approver or approver not in approvals.valid_statements(root, release_id, \"approver\"):", "if not approver:"),), "STABLE firmado"),
    M("rel-downgrade-off", "qce/recovery/release.py", (("if new_seq < old_seq:", "if False:"),), "sin downgrade de STABLE"),
    M("rel-id-binding-off", "qce/recovery/release.py", (('if release_id != expected or m.get("release_id") != expected:', 'if False:'),), "id ligado al contenido"),
    M("rel-symlink-tree-off", "qce/recovery/release.py", (('raise IntegrityError(f"symlink no permitido en el árbol versionado: {p.relative_to(root)}")', 'pass'),), "sin symlinks en el árbol"),
    M("rel-rollback-symlink-off", "qce/recovery/release.py", (('if src.is_symlink() or _has_symlink(root, rel):  # OJO: dst ya está resuelto; hay que mirar la ruta SIN resolver', 'if False:'),), "reversión sin symlinks"),
]
