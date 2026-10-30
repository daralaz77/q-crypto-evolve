"""Custodia de la clave privada del servidor TLS en el KeyStore (cifrado en reposo con el vault), no en un archivo.

Qué cambia: la clave nace dentro de la custodia (PKCS#8 en el KeyStore, propósito TLS), la CA solo recibe una CSR, y la clave
solo sale para construir un SSLContext. Python `ssl` exige un ARCHIVO de clave, así que en ese instante se escribe una copia
CIFRADA con una contraseña aleatoria que solo existe en memoria, se carga y se borra (sobrescrita) en el acto: en disco
nunca hay una clave privada en claro. La clave en claro sí está en la memoria del proceso mientras el contexto exista.

Ciclo de vida: provisión → certificado instalado → uso → rotación (la anterior pasa a RETIRED, no firma contextos nuevos) →
revocación (se borra el secreto y se dejan de atender conexiones nuevas) → destrucción. Caduca con el KeyStore.
"""
from __future__ import annotations

from . import tls13  # PRIMERO de todo: fija OPENSSL_CONF antes de que se importe nada que inicialice OpenSSL (cryptography, y también
#                      `secrets`/`hmac`/`hashlib` de la biblioteca estándar, que cargan la configuración de OpenSSL al importarse)
import os  # noqa: E402
import secrets  # noqa: E402
import ssl  # noqa: E402
import tempfile  # noqa: E402
import time  # noqa: E402
from pathlib import Path  # noqa: E402
from typing import Callable  # noqa: E402

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

from . import pki  # noqa: E402
from ..core.errors import KeyStateError, QCEError  # noqa: E402
from ..key_management.keystore import KeyStore, Purpose, State  # noqa: E402


class CertificateRejected(QCEError):
    """El certificado no corresponde a la clave custodiada, no es válido ahora o no cubre el nombre."""


class TlsKeyCustody:
    def __init__(self, store: KeyStore, certs_dir: Path, clock: Callable[[], float] = time.time) -> None:
        self._store, self._clock = store, clock
        self._certs = Path(certs_dir)
        self._certs.mkdir(parents=True, exist_ok=True)

    # ---- provisión --------------------------------------------------------------------------------------------------
    def provision_key(self, ttl_s: float, generation: int = 1, algorithm: str = "ecdsa-p256") -> str:
        key = pki.new_private_key(algorithm)
        der = key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        kid = self._store.create(Purpose.TLS, ttl_s, secret=der, generation=generation)
        self._store.activate(kid)  # ACTIVE pero inutilizable para servir hasta instalar un certificado
        return kid

    def _private_key(self, key_id: str, op: str):
        der = self._store.use(key_id, Purpose.TLS, op)  # estado, caducidad y propósito los decide el KeyStore
        return serialization.load_der_private_key(der, password=None)

    def csr_pem(self, key_id: str, name: str) -> bytes:
        key = self._private_key(key_id, "sign")
        csr = (x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
               .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False).sign(key, pki.signing_hash(key)))
        return csr.public_bytes(serialization.Encoding.PEM)

    def install_certificate(self, key_id: str, cert_pem: bytes, name: str) -> None:
        """Acepta solo un certificado de ESTA clave, vigente y que cubra `name`. El certificado es público (se guarda en claro)."""
        cert = x509.load_pem_x509_certificate(cert_pem)
        key = self._private_key(key_id, "sign")
        pub = serialization.PublicFormat.SubjectPublicKeyInfo
        if cert.public_key().public_bytes(serialization.Encoding.DER, pub) != key.public_key().public_bytes(serialization.Encoding.DER, pub):
            raise CertificateRejected("el certificado no corresponde a la clave custodiada")
        import datetime as dt
        now = dt.datetime.fromtimestamp(self._clock(), dt.timezone.utc)
        if not cert.not_valid_before_utc <= now <= cert.not_valid_after_utc:
            raise CertificateRejected("el certificado no está vigente")
        try:
            names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            names = []
        if name not in names:
            raise CertificateRejected("el certificado no cubre el nombre del servidor")
        (self._certs / f"{key_id}.pem").write_bytes(cert_pem)

    def provision_with_lab_ca(self, ca_key, ca_cert: x509.Certificate, name: str, ttl_s: float, generation: int = 1, algorithm: str = "ecdsa-p256") -> str:
        """Atajo de laboratorio: genera clave, firma la CSR con la CA de laboratorio e instala el certificado."""
        kid = self.provision_key(ttl_s, generation, algorithm)
        csr = x509.load_pem_x509_csr(self.csr_pem(kid, name))
        cert = pki.sign_csr(ca_key, ca_cert, csr)
        self.install_certificate(kid, cert.public_bytes(serialization.Encoding.PEM), name)
        return kid

    # ---- uso ------------------------------------------------------------------------------------------------------
    def active_id(self) -> str:
        """La clave TLS ACTIVE con certificado instalado y mayor generación."""
        ids = [k for k in self._store.all_ids() if self._store.info(k).purpose is Purpose.TLS and self._store.info(k).state is State.ACTIVE
               and (self._certs / f"{k}.pem").exists()]
        if not ids:
            raise KeyStateError("no hay clave TLS activa con certificado instalado")
        return max(ids, key=lambda k: self._store.info(k).generation)

    def server_context(self, key_id: str | None = None, client_ca: str | Path | None = None) -> ssl.SSLContext:
        kid = key_id or self.active_id()
        key = self._private_key(kid, "sign")  # RETIRED, REVOKED, caducada o de otro propósito → KeyStateError
        cert_path = self._certs / f"{kid}.pem"
        if not cert_path.exists():
            raise CertificateRejected("la clave no tiene certificado instalado")
        pub = serialization.PublicFormat.SubjectPublicKeyInfo
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        if cert.public_key().public_bytes(serialization.Encoding.DER, pub) != key.public_key().public_bytes(serialization.Encoding.DER, pub):
            raise CertificateRejected("el certificado instalado no corresponde a la clave (archivo manipulado)")
        password = secrets.token_bytes(32)  # solo en memoria
        with tempfile.TemporaryDirectory(prefix="qce-key-") as d:
            os.chmod(d, 0o700)
            kp = Path(d) / "k.pem"
            try:
                kp.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                 serialization.BestAvailableEncryption(password)))
                kp.chmod(0o600)
                return tls13.server_context(cert_path, kp, client_ca=client_ca, key_password=password)
            finally:
                if kp.exists():
                    kp.write_bytes(b"\0" * kp.stat().st_size)  # mejor esfuerzo; el directorio se borra al salir
                    kp.unlink()

    # ---- rotación y revocación ---------------------------------------------------------------------------------------
    def rotate(self, ca_key, ca_cert: x509.Certificate, name: str, ttl_s: float) -> str:
        """Nueva clave + certificado; la anterior pasa a RETIRED. Hay que pasar el contexto nuevo al servidor (`set_context`)."""
        old = self.active_id()
        new = self.provision_with_lab_ca(ca_key, ca_cert, name, ttl_s, generation=self._store.info(old).generation + 1)
        self._store.retire(old)
        return new

    def rotate_if_due(self, ca_key, ca_cert: x509.Certificate, name: str, ttl_s: float, renew_before_s: float, server: "tls13.TlsServer | None" = None) -> str | None:
        """Rotación automática: si a la clave activa le queda menos de `renew_before_s` de vida (o no hay ninguna), emite una nueva, retira la anterior y,
        si se da el servidor, le entrega el contexto nuevo. Devuelve el id nuevo o None si todavía no toca. Una clave ya caducada también se rota."""
        try:
            old = self.active_id()
            remaining = self._store.info(old).not_after - self._clock()
            if remaining > renew_before_s:
                return None
            new = self.rotate(ca_key, ca_cert, name, ttl_s)
        except KeyStateError:
            new = self.provision_with_lab_ca(ca_key, ca_cert, name, ttl_s)   # no hay activa o ya caducó: empezar de nuevo
        if server is not None:
            server.set_context(self.server_context(new))
        return new

    def certificate(self, key_id: str) -> x509.Certificate:
        return x509.load_pem_x509_certificate((self._certs / f"{key_id}.pem").read_bytes())

    def revoked_certificates(self) -> list[x509.Certificate]:
        """Certificados de las claves REVOCADAS: lo que la CA debe publicar en su CRL."""
        return [self.certificate(k) for k in self._store.all_ids()
                if self._store.info(k).purpose is Purpose.TLS and self._store.info(k).state is State.REVOKED and (self._certs / f"{k}.pem").exists()]

    def revoke(self, key_id: str, reason: str, server: "tls13.TlsServer | None" = None) -> None:
        """Borra el secreto y, si se indica el servidor, deja de atender conexiones nuevas (las abiertas las cierra quien revoca)."""
        self._store.revoke(key_id, reason)
        if server is not None:
            server.stop_accepting()
