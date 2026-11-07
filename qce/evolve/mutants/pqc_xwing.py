"""Mutantes de pqc / xwing (KEM X25519 + ML-KEM-768 según el borrador X-Wing). Archivo que rompen: qce/pqc/xwing.py."""
from ._base import Mutant as M

X = 'qce/pqc/xwing.py'
C = 'hashlib.sha3_256(ss_m + ss_x + ct_x + pk_x + LABEL).digest()'
MUTANTS = [
    M('xw-label-first', X, ((C, 'hashlib.sha3_256(LABEL + ss_m + ss_x + ct_x + pk_x).digest()'),), 'X-Wing: la etiqueta va AL FINAL de la entrada del combinador'),
    M('xw-combiner-drops-pk-x', X, ((C, 'hashlib.sha3_256(ss_m + ss_x + ct_x + LABEL).digest()'),), 'X-Wing: el combinador incluye la clave pública X25519'),
    M('xw-combiner-drops-ct-x', X, ((C, 'hashlib.sha3_256(ss_m + ss_x + pk_x + LABEL).digest()'),), 'X-Wing: el combinador incluye el texto cifrado X25519'),
    M('xw-combiner-drops-ss-x', X, ((C, 'hashlib.sha3_256(ss_m + ct_x + pk_x + LABEL).digest()'),), 'X-Wing: el combinador incluye el secreto X25519'),
    M('xw-label-wrong', X, (('bytes.fromhex("5c2e2f2f5e5c")', 'bytes.fromhex("5c2e2f2f5e5d")'),), 'X-Wing: la etiqueta es la del borrador'),
    M('xw-expand-x-offset', X, (('expanded[64:96]', 'expanded[63:95]'),), 'X-Wing: la clave X25519 sale de los bytes 64..96 de SHAKE256(semilla)'),
    M('xw-expand-mlkem-seed', X, (('expanded[:64]', 'expanded[32:96]'),), 'X-Wing: la semilla ML-KEM (d‖z) sale de los bytes 0..64'),
    M('xw-seed-len-check-off', X, (('        if len(seed) != SEED_LEN:', '        if False:'),), 'X-Wing: una semilla de otra longitud se rechaza'),
    M('xw-pk-len-check-off', X, (('    if len(public_bytes) != PK_LEN:', '    if False:'),), 'X-Wing: una clave pública de otra longitud se rechaza'),
    M('xw-ct-len-check-off', X, (('        if len(ct) != CT_LEN:', '        if False:'),), 'X-Wing: un texto cifrado de otra longitud se rechaza'),
    M('xw-decaps-lowest-order-leaks', X, (('        except ValueError as exc:  # punto de orden pequeño', '        except KeyError as exc:  # punto de orden pequeño'),), 'X-Wing: un punto X25519 de orden pequeño falla cerrado al decapsular'),
    M('xw-encaps-lowest-order-ignored', X, (('        raise AuthenticationFailure("componente X25519 inválido") from exc\n    ss_m, ct_m', '        ss_x = bytes(32)\n    ss_m, ct_m'),), 'X-Wing: un punto X25519 de orden pequeño falla cerrado al encapsular'),
    M('xw-invalid-mlkem-key-wrong-error', X, (('raise MalformedMessage("clave ML-KEM inválida") from exc', 'raise ValueError("clave ML-KEM inválida") from exc'),), 'X-Wing: una clave ML-KEM inválida se rechaza con MalformedMessage'),
    M('xw-decaps-uses-wrong-pk-x', X, (('return _combine(ss_m, ss_x, ct_x, self._pk_x)', 'return _combine(ss_m, ss_x, ct_x, ct_x)'),), 'X-Wing: la decapsulación liga la clave pública del receptor'),
    M('xw-destroy-noop', X, (('        self._seed = None\n        self._m = self._x = None  # type: ignore[assignment]', '        pass'),), 'X-Wing: destroy deja la clave inutilizable'),
    M('xw-decaps-after-destroy', X, (('        if self._seed is None:\n            raise AuthenticationFailure("clave X-Wing ya descartada")\n        if len(ct) != CT_LEN:', '        if len(ct) != CT_LEN:'),), 'X-Wing: no se puede decapsular tras destruir la clave'),
]
