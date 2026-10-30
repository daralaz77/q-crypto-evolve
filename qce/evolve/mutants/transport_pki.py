"""Mutantes de transport / pki (5). Archivos que rompen: qce/transport/pki.py."""
from ._base import Mutant as M

MUTANTS = [
    M('pki-ca-ski-missing', 'qce/transport/pki.py', (('            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)   # RFC 5280 §4.2.1.2: los clientes estrictos (Python ≥ 3.13 por defecto) lo exigen\n', ''),), 'PKI: la CA lleva Subject Key Identifier'),
    M('pki-leaf-aki-missing', 'qce/transport/pki.py', (('            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()), critical=False)   # RFC 5280 §4.2.1.1: obligatorio salvo en autofirmados\n', ''),), 'PKI: la hoja lleva Authority Key Identifier'),
    M('pki-leaf-ski-missing', 'qce/transport/pki.py', (('            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)\n            .sign(ca_key, signing_hash(ca_key)))\n    tag', '            .sign(ca_key, signing_hash(ca_key)))\n    tag'),), 'PKI: la hoja lleva Subject Key Identifier'),
    M('pki-crl-aki-missing', 'qce/transport/pki.py', (('    b = b.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()), critical=False)\n', ''),), 'PKI: la CRL lleva Authority Key Identifier'),
    M('pki-csr-aki-missing', 'qce/transport/pki.py', (('            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()), critical=False)\n            .add_extension(x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False)\n', '            .add_extension(x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False)\n'),), 'PKI: el certificado firmado desde un CSR lleva Authority Key Identifier'),
]
