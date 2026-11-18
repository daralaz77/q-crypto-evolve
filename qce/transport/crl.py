"""Comprobación previa de una lista de revocación (CRL) antes de confiar en ella.

OpenSSL ya rechaza un certificado si la CRL falta o está caducada (`VERIFY_CRL_CHECK_LEAF`), pero NO impide dos cosas que importan en la práctica:
  - una CRL ANTIGUA todavía vigente (sin las revocaciones recientes) que alguien con escritura sobre el archivo pone en lugar de la nueva (retroceso/rollback);
  - una CRL ilegible, de otra CA o con firma inválida, que solo se descubre cuando falla una conexión real.
`check_crl` falla cerrado ANTES de abrir el canal y devuelve el número de la CRL (`cRLNumber`, RFC 5280 §5.2.3) para que quien llama lo guarde y exija
que nunca disminuya (`min_number`). Fijar ese mínimo en un lugar que el atacante no controle es responsabilidad de quien despliega.
"""
from __future__ import annotations

import datetime as dt
from pathlib import Path

from cryptography import x509

from ..core.errors import QCEError


class CrlRejected(QCEError):
    """La CRL no es de confianza: no se abre ningún canal que dependa de ella."""


def _load_cas(ca_file: str | Path) -> list[x509.Certificate]:
    try:
        return x509.load_pem_x509_certificates(Path(ca_file).read_bytes())
    except (OSError, ValueError) as e:
        raise CrlRejected(f"no se pueden leer los certificados de la CA: {type(e).__name__}") from None


def check_crl(crl_file: str | Path, ca_file: str | Path, *, min_number: int | None = None, now: dt.datetime | None = None) -> int:
    """Verifica firma, emisor, vigencia y número de la CRL. Devuelve su `cRLNumber` (0 si no lo lleva y no se exigió un mínimo)."""
    now = now or dt.datetime.now(dt.timezone.utc)
    try:
        crl = x509.load_pem_x509_crl(Path(crl_file).read_bytes())
    except (OSError, ValueError) as e:
        raise CrlRejected(f"la CRL no se puede leer: {type(e).__name__}") from None
    issuers = [c for c in _load_cas(ca_file) if c.subject == crl.issuer]
    if not issuers:
        raise CrlRejected("la CRL no la emitió ninguna CA de confianza")
    if not any(_signed_by(crl, c) for c in issuers):
        raise CrlRejected("firma de la CRL inválida")
    if crl.last_update_utc > now:
        raise CrlRejected("la CRL aún no es válida (fecha de emisión futura)")
    if crl.next_update_utc is None or crl.next_update_utc <= now:
        raise CrlRejected("la CRL está caducada o no declara cuándo caduca")
    try:
        number = crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number
    except x509.ExtensionNotFound:
        number = None
    if min_number is not None:
        if number is None:
            raise CrlRejected("la CRL no lleva número y se exige uno (no se puede descartar un retroceso)")
        if number < min_number:
            raise CrlRejected(f"retroceso de la CRL: número {number} < mínimo {min_number}")
    return number or 0


def _signed_by(crl: x509.CertificateRevocationList, ca: x509.Certificate) -> bool:
    try:
        return crl.is_signature_valid(ca.public_key())
    except Exception:  # noqa: BLE001  (cualquier fallo al verificar = firma no válida)
        return False
