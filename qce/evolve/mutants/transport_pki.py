"""Mutantes de transport / pki (5). Archivos que rompen: qce/transport/pki.py."""
from ._base import Mutant as M

MUTANTS = [
    M('pki-ca-ski-missing', 'qce/transport/pki.py', (('            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)   # RFC 5280 §4.2.1.2: los clientes estrictos (Python ≥ 3.13 por defecto) lo exigen\n', ''),), 'PKI: la CA lleva Subject Key Identifier'),
    M('pki-leaf-aki-missing', 'qce/transport/pki.py', (('            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()), critical=False)  # type: ignore[arg-type]  # RFC 5280 §4.2.1.1: obligatorio salvo en autofirmados\n', ''),), 'PKI: la hoja lleva Authority Key Identifier'),
    M('pki-leaf-ski-missing', 'qce/transport/pki.py', (('            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)\n            .sign(ca_key, signing_hash(ca_key)))\n    tag', '            .sign(ca_key, signing_hash(ca_key)))\n    tag'),), 'PKI: la hoja lleva Subject Key Identifier'),
    M('pki-crl-aki-missing', 'qce/transport/pki.py', (('    b = b.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()), critical=False)  # type: ignore[arg-type]  # el stub acepta menos tipos de los que public_key() puede devolver\n', ''),), 'PKI: la CRL lleva Authority Key Identifier'),
    M('pki-csr-aki-missing', 'qce/transport/pki.py', (('            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()), critical=False)  # type: ignore[arg-type]  # el stub acepta menos tipos de los que public_key() puede devolver\n            .add_extension(x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False)\n', '            .add_extension(x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False)\n'),), 'PKI: el certificado firmado desde un CSR lleva Authority Key Identifier'),
    M("pki-private-key-world-readable", "qce/transport/pki.py", (("    atomic_write(path, data, mode)\n", "    atomic_write(path, data, 0o644)\n"),), "ronda 3: la clave privada de la PKI de laboratorio es 0600"),
    M("pki-write-follows-symlink", "qce/transport/pki.py", (("    atomic_write(path, data, mode)\n", "    path.write_bytes(data)\n    path.chmod(mode)\n"),), "ronda 3: sin ventana de permisos ni escritura a través de un symlink plantado"),
    M('pki-crl-number-missing', 'qce/transport/pki.py', (('    b = b.add_extension(x509.CRLNumber(number), critical=False)\n', ''),), 'la CRL emitida lleva cRLNumber'),
    M('crl-signature-unchecked', 'qce/transport/crl.py', (('if not any(_signed_by(crl, c) for c in issuers):', 'if False:'),), 'firma de la CRL'),
    M('crl-issuer-unchecked', 'qce/transport/crl.py', (('if c.subject == crl.issuer]', 'if True]'),), 'emisor de la CRL'),
    M('crl-no-issuer-not-reported', 'qce/transport/crl.py', (('    if not issuers:\n', '    if False:\n'),), 'CRL de una CA que no es de confianza'),
    M('crl-future-allowed', 'qce/transport/crl.py', (('if crl.last_update_utc > now:', 'if False:'),), 'CRL con fecha futura'),
    M('crl-expired-allowed', 'qce/transport/crl.py', (('if crl.next_update_utc is None or crl.next_update_utc <= now:', 'if False:'),), 'CRL caducada'),
    M('crl-rollback-allowed', 'qce/transport/crl.py', (('if number < min_number:', 'if False:'),), 'retroceso del número de CRL'),
    M('crl-rollback-boundary', 'qce/transport/crl.py', (('if number < min_number:', 'if number <= min_number:'),), 'el mismo número es válido'),
    M('crl-number-missing-allowed', 'qce/transport/crl.py', (('        if number is None:\n            raise CrlRejected("la CRL no lleva número', '        if False:\n            raise CrlRejected("la CRL no lleva número'),), 'CRL sin número cuando se exige uno'),
    M('crl-min-ignored', 'qce/transport/crl.py', (('    if min_number is not None:\n', '    if False:\n'),), 'mínimo de número exigido'),
    M('crl-read-oserror-uncaught', 'qce/transport/crl.py', (('    except (OSError, ValueError) as e:\n        raise CrlRejected(f"la CRL no se puede leer', '    except ValueError as e:\n        raise CrlRejected(f"la CRL no se puede leer'),), 'CRL ausente = CrlRejected'),
    M('crl-read-valueerror-uncaught', 'qce/transport/crl.py', (('    except (OSError, ValueError) as e:\n        raise CrlRejected(f"la CRL no se puede leer', '    except OSError as e:\n        raise CrlRejected(f"la CRL no se puede leer'),), 'CRL ilegible = CrlRejected'),
    M('crl-ca-oserror-uncaught', 'qce/transport/crl.py', (('    except (OSError, ValueError) as e:\n        raise CrlRejected(f"no se pueden leer los certificados', '    except ValueError as e:\n        raise CrlRejected(f"no se pueden leer los certificados'),), 'CA ausente = CrlRejected'),
    M('crl-ca-valueerror-uncaught', 'qce/transport/crl.py', (('    except (OSError, ValueError) as e:\n        raise CrlRejected(f"no se pueden leer los certificados', '    except OSError as e:\n        raise CrlRejected(f"no se pueden leer los certificados'),), 'CA ilegible = CrlRejected'),
]
