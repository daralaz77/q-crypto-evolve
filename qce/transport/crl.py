"""Comprobación previa de una lista de revocación (CRL) antes de confiar en ella.

OpenSSL ya rechaza un certificado si la CRL falta o está caducada (`VERIFY_CRL_CHECK_LEAF`), pero NO impide dos cosas que importan en la práctica:
  - una CRL ANTIGUA todavía vigente (sin las revocaciones recientes) que alguien con escritura sobre el archivo pone en lugar de la nueva (retroceso/rollback);
  - una CRL ilegible, de otra CA o con firma inválida, que solo se descubre cuando falla una conexión real.
`check_crl` falla cerrado ANTES de abrir el canal y devuelve el número de la CRL (`cRLNumber`, RFC 5280 §5.2.3) para que quien llama lo guarde y exija
que nunca disminuya (`min_number`). Fijar ese mínimo en un lugar que el atacante no controle es responsabilidad de quien despliega.
"""
from __future__ import annotations

import datetime as dt
import fcntl
import json
from pathlib import Path

from cryptography import x509

from ..core.atomic import atomic_write
from ..core.errors import QCEError


class CrlRejected(QCEError):
    """La CRL no es de confianza: no se abre ningún canal que dependa de ella."""


def _load_cas(ca_file: str | Path) -> list[x509.Certificate]:
    try:
        return x509.load_pem_x509_certificates(Path(ca_file).read_bytes())
    except (OSError, ValueError) as e:
        raise CrlRejected(f"no se pueden leer los certificados de la CA: {type(e).__name__}") from None


class CrlPin:
    """Ancla LOCAL del número de CRL: recuerda, por emisor, el `cRLNumber` más alto aceptado y rechaza cualquier lista con uno menor.

    Así quien despliega no tiene que fijar `min_crl_number` a mano: la primera CRL válida fija el suelo y desde entonces solo se puede avanzar. El suelo solo
    sube DESPUÉS de que la CRL pasó todas las demás comprobaciones (firma, emisor, vigencia): una lista falsa no puede subirlo. Archivo 0600, escritura atómica
    y con cerrojo; si no se puede leer, se rechaza (no se acepta nada a ciegas).
    LÍMITE: quien pueda reescribir este archivo puede bajar el suelo; guárdalo donde el atacante que cambia la CRL no escriba."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def _read(self) -> dict[str, int]:
        if not self.path.exists():
            return {}
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(data, dict) or not all(isinstance(k, str) and type(v) is int and v >= 0 for k, v in data.items()):
                raise ValueError("formato")
            return data
        except (OSError, ValueError):
            raise CrlRejected("el ancla local de CRL no se puede leer: no se acepta ninguna lista a ciegas") from None

    def check(self, issuer: str, number: int | None) -> int:
        """Rechaza el retroceso y, si el número avanza, lo recuerda. Devuelve el suelo vigente tras la comprobación."""
        if number is None:
            raise CrlRejected("la CRL no lleva número: no se puede anclar (no se descarta un retroceso)")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path.with_suffix(self.path.suffix + ".lock"), "w") as lk:
            fcntl.flock(lk, fcntl.LOCK_EX)
            seen = self._read()
            floor = seen.get(issuer, 0)
            if number < floor:
                raise CrlRejected(f"retroceso de la CRL: número {number} < el más alto visto {floor}")
            if number > floor:
                seen[issuer] = number
                atomic_write(self.path, json.dumps(seen, sort_keys=True).encode("utf-8"), 0o600)
            return max(number, floor)


def check_crl(crl_file: str | Path, ca_file: str | Path, *, min_number: int | None = None, now: dt.datetime | None = None, pin: CrlPin | None = None) -> int:
    """Verifica firma, emisor, vigencia y número de la CRL. Devuelve su `cRLNumber` (0 si no lo lleva y no se exigió un mínimo).
    Con `pin`, además rechaza un número menor que el más alto visto antes y lo recuerda si avanza (solo tras pasar todo lo demás)."""
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
    if pin is not None:
        pin.check(crl.issuer.rfc4514_string(), number)   # lo ÚLTIMO: una lista que no pasó lo anterior no puede subir el suelo
    return number or 0


def _signed_by(crl: x509.CertificateRevocationList, ca: x509.Certificate) -> bool:
    try:
        return crl.is_signature_valid(ca.public_key())
    except Exception:  # noqa: BLE001  (cualquier fallo al verificar = firma no válida)
        return False
