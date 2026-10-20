"""Mutantes de key / management (13). Archivos que rompen: qce/key_management/keystore.py, qce/key_management/vault.py."""
from ._base import Mutant as M

MUTANTS = [
    M("keys-purpose-check-off", "qce/key_management/keystore.py", (("if rec.purpose is not purpose:", "if False:"),), "separación de claves"),
    M("keys-state-check-off", "qce/key_management/keystore.py", (("if rec.state is not State.ACTIVE:", "if rec.state is State.DESTROYED:"),), "solo ACTIVE produce"),
    M("keys-expiry-boundary", "qce/key_management/keystore.py", (("if self._clock() >= rec.not_after:", "if self._clock() > rec.not_after:"),), "caducidad"),
    M("keys-expiry-off", "qce/key_management/keystore.py", (("if self._clock() >= rec.not_after:", "if False:"),), "caducidad"),
    M("keys-revoked-readable", "qce/key_management/keystore.py", (("if rec.state not in (State.ACTIVE, State.RETIRED):", "if rec.state is State.DESTROYED:"),), "revocación"),
    M("keys-no-zeroize-on-revoke", "qce/key_management/keystore.py", (("if new in (State.REVOKED, State.DESTROYED):", "if new in (State.DESTROYED,):"),), "borrado"),
    M("keys-aad-ignores-generation", "qce/key_management/keystore.py", (("key_id.encode() + generation.to_bytes(4, \"big\") + aad", "key_id.encode() + aad"),), "enlace de generación",
      "la generación ya va ligada a la clave concreta (un key_id = una generación); redundancia defensiva"),
    M("vault-rollback-check-off", "qce/key_management/vault.py", (("if epoch < min_epoch:", "if False:"),), "anti-restauración"),
    M("vault-kdf-floor-off", "qce/key_management/vault.py", (("n < 2**14 or n > 2**17 or n & (n - 1)", "n > 2**17 or n & (n - 1)"),), "parámetros KDF no degradables"),
    M("vault-kdf-ceiling-off", "qce/key_management/vault.py", (("n < 2**14 or n > 2**17 or n & (n - 1)", "n < 2**14 or n & (n - 1)"),), "KDF no inflable (DoS)"),
    M("vault-kdf-pow2-off", "qce/key_management/vault.py", (("n < 2**14 or n > 2**17 or n & (n - 1)", "n < 2**14 or n > 2**17"),), "n potencia de 2"),
    M("vault-header-not-aad", "qce/key_management/vault.py", (("decrypt(nonce, data[45:], header)", "decrypt(nonce, data[45:], b'')"),), "cabecera autenticada"),
    M("ks-rotate-state-off", "qce/key_management/keystore.py", (("if old.state is not State.ACTIVE:  # antes de crear nada", "if False:  # antes de crear nada"),), "rotate sin huérfanos"),
]
