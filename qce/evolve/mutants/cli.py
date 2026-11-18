"""Mutantes de cli (1). Archivos que rompen: qce/cli.py."""
from ._base import Mutant as M

MUTANTS = [
    M('cer-cli-sequence-dropped', 'qce/cli.py', (('a.verdict, a.notes, a.sequence)', 'a.verdict, a.notes)'),), 'ceremonia: el CLI pasa la secuencia a la firma'),
    M('cer-cli-noninteractive-allowed', 'qce/cli.py', (('if not sys.stdin.isatty() and os.environ.get("QCE_ALLOW_NONINTERACTIVE_SIGN") != "1":', 'if False:'),), 'ceremonia: firmar exige terminal interactiva'),
    M('cli-root-guard-off', 'qce/cli.py', (('    if not _is_project_root(ROOT):', '    if False:'),), 'la CLI no corre fuera de un clon'),
    M('cli-root-without-gates', 'qce/cli.py', (('(root / "gates.json").is_file() and (root / "qce").is_dir()', '(root / "qce").is_dir()'),), 'el clon se reconoce por gates.json'),
    M('cli-root-without-package', 'qce/cli.py', (('(root / "gates.json").is_file() and (root / "qce").is_dir()', '(root / "gates.json").is_file()'),), 'el clon se reconoce por qce/'),
    M('cli-qce-root-env-ignored', 'qce/cli.py', (('if os.environ.get("QCE_ROOT") else', 'if False else'),), 'QCE_ROOT apunta la CLI a un clon'),
]
