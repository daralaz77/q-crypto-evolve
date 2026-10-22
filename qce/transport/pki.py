"""PKI de LABORATORIO (ECDSA P-256) para pruebas y demostraciones. No es una infraestructura de producción:
las claves privadas se escriben en disco con permisos 0600 y no pasan por el KeyStore (brecha declarada en LIMITATIONS.md).
"""
from __future__ import annotations

import datetime as dt
import ipaddress
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

UTC = dt.timezone.utc


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _write(path: Path, data: bytes, mode: int = 0o600) -> Path:
    path.write_bytes(data)
    path.chmod(mode)
    return path


def _key_pem(key) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def issue_ca(directory: Path, cn: str = "QCE lab CA", days: int = 1) -> tuple[Path, ec.EllipticCurvePrivateKey, x509.Certificate]:
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(UTC)
    cert = (x509.CertificateBuilder().subject_name(_name(cn)).issuer_name(_name(cn)).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(minutes=1)).not_valid_after(now + dt.timedelta(days=days))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True, content_commitment=False, key_encipherment=False,
                                         data_encipherment=False, key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)   # RFC 5280 §4.2.1.2: los clientes estrictos (Python ≥ 3.13 por defecto) lo exigen
            .sign(key, hashes.SHA256()))
    path = _write(directory / "ca.pem", cert.public_bytes(serialization.Encoding.PEM), 0o644)
    return path, key, cert


def issue_leaf(directory: Path, ca_key, ca_cert: x509.Certificate, name: str, *, server: bool, days: int = 1,
               not_before_offset: dt.timedelta = dt.timedelta(minutes=-1)) -> tuple[Path, Path]:
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(UTC)
    san = [x509.DNSName(name)] if server else [x509.DNSName(name)]
    if server:
        san.append(x509.IPAddress(ipaddress.ip_address("127.0.0.1")))
    eku = ExtendedKeyUsageOID.SERVER_AUTH if server else ExtendedKeyUsageOID.CLIENT_AUTH
    cert = (x509.CertificateBuilder().subject_name(_name(name)).issuer_name(ca_cert.subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now + not_before_offset).not_valid_after(now + not_before_offset + dt.timedelta(days=days))
            .add_extension(x509.SubjectAlternativeName(san), critical=False)
            .add_extension(x509.ExtendedKeyUsage([eku]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()), critical=False)   # RFC 5280 §4.2.1.1: obligatorio salvo en autofirmados
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))
    tag = ("srv-" if server else "cli-") + name
    cp = _write(directory / f"{tag}.pem", cert.public_bytes(serialization.Encoding.PEM), 0o644)
    kp = _write(directory / f"{tag}.key", _key_pem(key))
    return cp, kp


def sign_csr(ca_key, ca_cert: x509.Certificate, csr: x509.CertificateSigningRequest, *, server: bool = True, days: int = 1) -> x509.Certificate:
    """Emite un certificado de hoja para el CSR (la clave privada nunca sale de quien lo generó). Solo laboratorio."""
    if not csr.is_signature_valid:
        raise ValueError("CSR con firma inválida")
    now = dt.datetime.now(UTC)
    san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    eku = ExtendedKeyUsageOID.SERVER_AUTH if server else ExtendedKeyUsageOID.CLIENT_AUTH
    return (x509.CertificateBuilder().subject_name(csr.subject).issuer_name(ca_cert.subject).public_key(csr.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(minutes=1)).not_valid_after(now + dt.timedelta(days=days))
            .add_extension(san, critical=False).add_extension(x509.ExtendedKeyUsage([eku]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))


def issue_crl(directory: Path, ca_key, ca_cert: x509.Certificate, revoked: list[x509.Certificate], days: int = 1, name: str = "crl.pem") -> Path:
    """Lista de revocación (CRL) de la CA de laboratorio con los certificados indicados."""
    now = dt.datetime.now(UTC)
    b = (x509.CertificateRevocationListBuilder().issuer_name(ca_cert.subject).last_update(now - dt.timedelta(minutes=1))
         .next_update(now + dt.timedelta(days=days)))
    for cert in revoked:
        b = b.add_revoked_certificate(x509.RevokedCertificateBuilder().serial_number(cert.serial_number).revocation_date(now).build())
    b = b.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()), critical=False)
    crl = b.sign(ca_key, hashes.SHA256())
    return _write(directory / name, crl.public_bytes(serialization.Encoding.PEM), 0o644)
