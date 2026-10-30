"""Mutantes de la revisión de calidad y seguridad (2026-10-30): candados de QIL1 y del broker QKD, ancla de epoch, escritura atómica, validación de release_id/rol y
agregación IPv6 del límite de tasa. Cada uno rompe UNA garantía."""
from ._base import Mutant as M

QL, BR, VA, AP, RL = ("qce/transport/qkd_layer.py", "qce/qkd/broker.py", "qce/key_management/vault.py", "qce/security/approvals.py", "qce/core/ratelimit.py")


def broker_unlocked(method: str):
    return M(f"broker-{method}-unlocked", BR, ((f"    @_locked\n    def {method}(", f"    def {method}("),), f"KeyBroker.{method} se serializa con el candado del broker")


MUTANTS = [
    M("qil1-layer-write-unlocked", QL, (("        with self._wlock:\n", "        if True:\n"),), "QIL1: escribir (contador-nonce, cifrar, enviar) es una sección crítica"),
    M("qil1-layer-read-unlocked", QL, (("        with self._rlock:\n", "        if True:\n"),), "QIL1: leer (marco, contador, descifrar) es una sección crítica"),
    *[broker_unlocked(m) for m in ("reserve", "peek", "release", "revoke", "metadata", "status")],
    M("broker-consume-unlocked", BR, (("        with self._lock:  # comprobar la reserva", "        if True:  # comprobar la reserva"),), "KeyBroker.consume: comprobar la reserva y marcar CONSUMED es atómico"),
    M("broker-register-unlocked", BR, (("            with self._lock:  # comprobar «duplicado»", "            if True:  # comprobar «duplicado»"),), "KeyBroker.refill: comprobar duplicado y registrar la clave es atómico"),
    M("anchor-advance-unlocked", VA, (("            fcntl.flock(lk, fcntl.LOCK_EX)\n            if epoch < self.read():", "            if epoch < self.read():"),), "EpochAnchor: leer-comparar-reemplazar va bajo flock (no retrocede entre procesos)"),
    M("anchor-write-nonatomic", VA, (('            atomic_write(self.path, json.dumps({"epoch": epoch}).encode(), prefix=".epoch-")', '            self.path.write_text(json.dumps({"epoch": epoch}), encoding="utf-8")'),), "EpochAnchor: escritura atómica"),
    M("vault-save-nonatomic", VA, (('    atomic_write(path, blob, prefix=".vault-")\n', "    Path(path).write_bytes(blob)\n"),), "vault: escritura atómica"),
    M("approvals-sign-release-id-unchecked", AP, (("    _check_release_id(release_id)\n    sig = key.sign", "    sig = key.sign"),), "declaraciones: release_id validado al firmar (sin rutas ni comodines)"),
    M("approvals-valid-release-id-unchecked", AP, (("""con el rol registrado.\"\"\"\n    _check_release_id(release_id)\n""", """con el rol registrado.\"\"\"\n"""),), "declaraciones: release_id validado al verificar"),
    M("approvals-veto-release-id-unchecked", AP, (("""BLOQUEA aunque otro haya aceptado.\"\"\"\n    _check_release_id(release_id)\n""", """BLOQUEA aunque otro haya aceptado.\"\"\"\n"""),), "declaraciones: release_id validado al buscar vetos"),
    M("approvals-sign-role-unchecked", AP, (('    if role not in ROLES:\n        raise QCEError("rol inválido")\n    _check_release_id(release_id)\n', "    _check_release_id(release_id)\n"),), "declaraciones: el rol se valida al firmar (no es una ruta)"),
    M("approvals-registry-nonatomic", AP, (("    atomic_write(reg, json.dumps(data, indent=2, sort_keys=True).encode(), mode=0o644)", "    reg.write_text(json.dumps(data, indent=2, sort_keys=True), encoding=\"utf-8\")"),), "registro de confianza: escritura atómica"),
    M("ratelimit-ipv6-per-address", RL, (("            return str(ip.ipv4_mapped) if ip.ipv4_mapped else str(ipaddress.ip_network((ip, 64), strict=False))\n", "            return str(ip)\n"),), "límite de tasa: un /64 de IPv6 es UN origen"),
    M("ratelimit-origin-not-normalized", RL, (("        origin = self.origin_key(origin)\n", ""),), "límite de tasa: el origen se normaliza antes de contar"),
]
