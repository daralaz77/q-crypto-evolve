"""Mutantes de symmetric (7). Archivos que rompen: qce/symmetric/aead.py."""
from ._base import Mutant as M

MUTANTS = [
    M("replay-seen-check-off", "qce/symmetric/aead.py", (("if seq in self._seen:", "if False:"),), "anti-repetición"),
    M("replay-window-boundary", "qce/symmetric/aead.py", (("seq <= self.highest - self.size", "seq < self.highest - self.size"),), "ventana"),
    M("replay-never-recorded", "qce/symmetric/aead.py", (("            self._window.accept(seq)\n            return pt", "            return pt"),), "anti-repetición"),
    M("nonce-counter-frozen", "qce/symmetric/aead.py", (("self._next += 1", "self._next += 0"),), "unicidad de nonce"),
    M("rekey-limit-off", "qce/symmetric/aead.py", (("if self._next >= self._max:", "if False:"),), "límite por clave"),
    M("aead-key-size-off", "qce/symmetric/aead.py", (("if len(key) != 32:", "if False:"),), "256 bits"),
    M("CANARY-noop", "qce/symmetric/aead.py", (("if seq in self._seen:", "if (seq in self._seen):"),), "canario: un mutante sin efecto DEBE sobrevivir", "canary"),
]
