"""Mutantes de transport / tls13 (14). Archivos que rompen: qce/transport/tls13.py."""
from ._base import Mutant as M

MUTANTS = [
    M("tls-key-password-dropped", "qce/transport/tls13.py", (('ctx.load_cert_chain(str(certfile), str(keyfile), password=key_password)', 'ctx.load_cert_chain(str(certfile), str(keyfile))'),), "transporte: clave cifrada"),
    M("tls-server-stop-accepting-noop", "qce/transport/tls13.py", (('    def stop_accepting(self) -> None:\n        """Revocación: ninguna conexión nueva se atiende (las abiertas deben cerrarse por quien revoca)."""\n        self._ctx = None', '    def stop_accepting(self) -> None:\n        """Revocación: ninguna conexión nueva se atiende (las abiertas deben cerrarse por quien revoca)."""\n        pass'),), "transporte: parada de conexiones nuevas"),
    M("tls-client-min-version-off", "qce/transport/tls13.py", (('    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)  # check_hostname=True y CERT_REQUIRED por defecto\n    ctx.minimum_version = ssl.TLSVersion.TLSv1_3\n', '    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)  # check_hostname=True y CERT_REQUIRED por defecto\n'),), "TLS 1.3 mínimo (cliente)"),
    M("tls-server-min-version-off", "qce/transport/tls13.py", (('    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)\n    ctx.minimum_version = ssl.TLSVersion.TLSv1_3\n', '    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)\n'),), "TLS 1.3 mínimo (servidor)"),
    M("tls-client-verify-off", "qce/transport/tls13.py", (('    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)  # check_hostname=True y CERT_REQUIRED por defecto\n', '    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)  # check_hostname=True y CERT_REQUIRED por defecto\n    ctx.check_hostname = False\n    ctx.verify_mode = ssl.CERT_NONE\n'),), "verificación de certificado"),
    M("tls-tickets-on", "qce/transport/tls13.py", (('    ctx.num_tickets = 0  # sin reanudación de sesión: cada conexión hace un apretón completo y fresco\n', ''),), "sin reanudación"),
    M("tls-attestation-skipped", "qce/transport/tls13.py", (('        _export_config()\n        _attest()\n        _attested = True', '        _export_config()\n        _attested = True'),), "atestación obligatoria"),
    M("tls-attestation-ignores-failures", "qce/transport/tls13.py", (('    bad = [msg for msg, got, want in checks if got != want]', '    bad = []'),), "atestación efectiva"),
    M("tls-mtls-off", "qce/transport/tls13.py", (('        ctx.verify_mode = ssl.CERT_REQUIRED\n        ctx.load_verify_locations(str(client_ca))', '        ctx.load_verify_locations(str(client_ca))'),), "autenticación mutua"),
    M("tls-frame-limit-off", "qce/transport/tls13.py", (('    if n > max_size:\n', '    if False:\n'),), "límite de mensaje"),
    M("tls-config-allows-x25519", "qce/transport/tls13.py", (('Groups = {HYBRID_GROUP}\n', 'Groups = X25519:{HYBRID_GROUP}\n'),), "grupo híbrido único"),
    M("tls-config-allows-tls12", "qce/transport/tls13.py", (('MinProtocol = TLSv1.3\n', 'MinProtocol = TLSv1.2\n'),), "TLS 1.3 por configuración", "Python fija su propio mínimo (TLS 1.2) al crear el contexto y sobrescribe MinProtocol; TLS 1.2 queda bloqueado igualmente por el grupo híbrido único y por minimum_version en nuestros contextos (defensa en profundidad para otros clientes de la misma configuración)"),
    M("tls-crl-check-off", "qce/transport/tls13.py", (("        ctx.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF", "        pass"),), "transporte: comprobación de CRL"),
    M("tls-crl-not-loaded", "qce/transport/tls13.py", (("    if crl_file is not None:\n        ctx.load_verify_locations(str(crl_file))\n", "    if crl_file is not None:\n"),), "transporte: CRL cargada (falla cerrado)"),
]
