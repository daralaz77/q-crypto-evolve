"""Mutantes de core / openssl_advisories (aviso de OpenSSL por debajo del parche) y de la salida de `qce tls-check`. Archivos que rompen: qce/core/openssl_advisories.py, qce/cli.py."""
from ._base import Mutant as M

A = 'qce/core/openssl_advisories.py'
MUTANTS = [
    M('adv-floor-compare-le', A, (('    if patch < floor:', '    if patch <= floor:'),), 'avisos OpenSSL: la versión que YA corrige el aviso no se marca como vulnerable'),
    M('adv-floor-compare-gt', A, (('    if patch < floor:', '    if patch > floor:'),), 'avisos OpenSSL: una versión por debajo del parche sí se marca'),
    M('adv-parse-patch-shift', A, (('(number >> 4) & 0xFF', '(number >> 8) & 0xFF'),), 'avisos OpenSSL: el parche se lee de los bits correctos de OPENSSL_VERSION_NUMBER'),
    M('adv-parse-minor-shift', A, (('(number >> 20) & 0xFF', '(number >> 16) & 0xFF'),), 'avisos OpenSSL: la rama menor se lee de los bits correctos'),
    M('adv-table-36-floor-lowered', A, (('(3, 6): (5, "CVE-2026-84782", "alta"),', '(3, 6): (4, "CVE-2026-84782", "alta"),'),), 'avisos OpenSSL: el piso de la rama 3.6 es el del aviso'),
    M('adv-unknown-branch-reported-ok', A, (('return Assessment(version, "no_data", f"OpenSSL {version}: la tabla', 'return Assessment(version, "ok", f"OpenSSL {version}: la tabla'),), 'avisos OpenSSL: sin datos NO se presenta como «al día»'),
    M('adv-cli-strict-ignored', 'qce/cli.py', (('return 3 if (below and strict) else 0', 'return 3 if below else 0'),), 'tls-check: sin --strict un aviso no cambia el código de salida'),
    M('adv-cli-strict-never-fails', 'qce/cli.py', (('return 3 if (below and strict) else 0', 'return 0'),), 'tls-check --strict sale con 3 si una OpenSSL está por debajo'),
    M('adv-cli-last-library-wins', 'qce/cli.py', (('below = below or result.status == "below_floor"', 'below = result.status == "below_floor"'),), 'tls-check: basta con que UNA de las dos OpenSSL esté por debajo'),
    M('adv-cli-stale-table-silent', 'qce/cli.py', (('    if adv.table_age_days() > adv.STALE_AFTER_DAYS:', '    if False:'),), 'tls-check avisa cuando la tabla de avisos está desactualizada'),
]
