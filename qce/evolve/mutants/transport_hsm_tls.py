"""Mutantes de transport / hsm / tls (18). Archivos que rompen: qce/transport/hsm_tls.py."""
from ._base import Mutant as M

MUTANTS = [
    M('hsm-uri-prefix-off', 'qce/transport/hsm_tls.py', (('if not key_uri.startswith("pkcs11:") or "type=private" not in key_uri:', 'if False:'),), 'HSM: solo URI pkcs11:'),
    M('hsm-uri-private-type-off', 'qce/transport/hsm_tls.py', ((' or "type=private" not in key_uri:', ':'),), 'HSM: solo clave privada'),
    M('hsm-file-exists-check-off', 'qce/transport/hsm_tls.py', (('            if not Path(f).is_file():', '            if False:'),), 'HSM: archivos existentes'),
    M('hsm-extractable-check-off', 'qce/transport/hsm_tls.py', (('            if key_is_extractable(c, pkey):', '            if False:'),), 'HSM: rechazar claves exportables'),
    M('hsm-extractable-rsa-only', 'qce/transport/hsm_tls.py', (('for name in (b"d", b"priv"):', 'for name in (b"d",):'),), 'HSM: exportabilidad EC'),
    M('hsm-extractable-ec-only', 'qce/transport/hsm_tls.py', (('for name in (b"d", b"priv"):', 'for name in (b"priv",):'),), 'HSM: exportabilidad RSA'),
    M('hsm-extractable-always-false', 'qce/transport/hsm_tls.py', (('            return True\n        P._errors(crypto)', '            return False\n        P._errors(crypto)'),), 'HSM: la clave de software se detecta'),
    M('hsm-cert-match-check-off', 'qce/transport/hsm_tls.py', (('            if l.SSL_CTX_check_private_key(self._ctx) != 1:', '            if False:'),), 'HSM: certificado = clave del token'),
    M('hsm-cert-load-check-off', 'qce/transport/hsm_tls.py', (('            if l.SSL_CTX_use_certificate_chain_file(self._ctx, str(cert_file).encode()) != 1:', '            if False:'),), 'HSM: certificado válido'),
    M('hsm-no-key-check-off', 'qce/transport/hsm_tls.py', (('            if not pkey:\n                raise PolicyViolation("el token no tiene esa clave privada', '            if False:\n                raise PolicyViolation("el token no tiene esa clave privada'),), 'HSM: la clave existe'),
    M('hsm-up-ref-off', 'qce/transport/hsm_tls.py', (('        l.SSL_CTX_up_ref(self._ctx)           # cada conexión cierra SU referencia al contexto\n', ''),), 'HSM: cada conexión tiene su referencia'),
    M('hsm-attest-off', 'qce/transport/hsm_tls.py', (('            P._attest(conn, self._suite, self._group, require_psk=False)\n', '            pass\n'),), 'HSM: atestación tras el apretón'),
    M('hsm-libctx-cache-off', 'qce/transport/hsm_tls.py', (('            if key not in _LIBCTX:', '            if True:'),), 'HSM: un contexto de biblioteca por configuración'),
    M('hsm-libctx-freed-on-close', 'qce/transport/hsm_tls.py', (('        self._libctx = None   # NO se libera: el módulo PKCS#11 vive hasta el final del proceso', '        c.OSSL_LIB_CTX_free(self._libctx)\n        self._libctx = None'),), 'HSM: el módulo no se descarga (fork)'),
    M('hsm-ssl-ctx-not-freed', 'qce/transport/hsm_tls.py', (('        if self._ctx:\n            l.SSL_CTX_free(self._ctx)\n            self._ctx = None', '        if self._ctx:\n            self._ctx = None'),), 'HSM: se libera el SSL_CTX'),
    M('hsm-suite-unchecked', 'qce/transport/hsm_tls.py', (('        P._check_suite(suite)\n        P._check_group(group)\n        if not key_uri', '        P._check_group(group)\n        if not key_uri'),), 'HSM: suite permitida'),
    M('hsm-group-unchecked', 'qce/transport/hsm_tls.py', (('        P._check_group(group)\n        if not key_uri', '        if not key_uri'),), 'HSM: grupo permitido'),
    M('hsm-stored-key-type-wrong', 'qce/transport/hsm_tls.py', (('OSSL_STORE_INFO_PKEY = 4', 'OSSL_STORE_INFO_PKEY = 3'),), 'HSM: tipo de objeto clave privada'),
]
