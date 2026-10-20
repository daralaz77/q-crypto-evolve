"""Mutantes de cli (1). Archivos que rompen: qce/cli.py."""
from ._base import Mutant as M

MUTANTS = [
    M('cer-cli-noninteractive-allowed', 'qce/cli.py', (('if not sys.stdin.isatty() and os.environ.get("QCE_ALLOW_NONINTERACTIVE_SIGN") != "1":', 'if False:'),), 'ceremonia: firmar exige terminal interactiva'),
]
