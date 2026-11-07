"""X-Wing: KEM híbrido X25519 + ML-KEM-768 según draft-connolly-cfrg-xwing-kem-11 (IETF CFRG, borrador informativo, NO es un RFC).

POR QUÉ EXISTE: el KEM híbrido propio de `qce/pqc/hybrid.py` usa un combinador diseñado aquí (HKDF sobre todo el texto cifrado y la clave pública). X-Wing es un combinador
con diseño público y análisis publicado. Este módulo es una primitiva AUTÓNOMA: NO está conectada al apretón QCE1 ni a ninguna suite (conectarla cambiaría el protocolo y exigiría
actualizar el modelo formal; ver docs/XWING.md).

Diferencias deliberadas con `hybrid.py` (no mezclar): la clave pública y el texto cifrado van en orden ML-KEM ‖ X25519 (el híbrido propio: X25519 ‖ ML-KEM); el secreto es
SHA3-256(ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ etiqueta) y NO incluye ct_M ni pk_M (X-Wing se apoya en que ML-KEM es IND-CCA); la clave privada es una semilla de 32 bytes.

Límites: el borrador puede cambiar (sus vectores están marcados TODO por los autores); sin revisión humana; el borrado de memoria es de mejor esfuerzo (LIMITATIONS.md).
Desviación declarada: la decapsulación falla cerrada (AuthenticationFailure) ante un punto X25519 de orden pequeño, cosa que el borrador no exige.
"""
from __future__ import annotations

import hashlib

from cryptography.hazmat.primitives.asymmetric import mlkem, x25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ..core.errors import AuthenticationFailure, MalformedMessage

LABEL = bytes.fromhex("5c2e2f2f5e5c")      # «\./» seguido de «/^\» (6 bytes), va AL FINAL de la entrada del combinador
SEED_LEN = 32
MLKEM_PK, MLKEM_CT, X_LEN = 1184, 1088, 32
PK_LEN = MLKEM_PK + X_LEN                   # 1216
CT_LEN = MLKEM_CT + X_LEN                   # 1120
SS_LEN = 32


def _combine(ss_m: bytes, ss_x: bytes, ct_x: bytes, pk_x: bytes) -> bytes:
    return hashlib.sha3_256(ss_m + ss_x + ct_x + pk_x + LABEL).digest()


def _expand(seed: bytes) -> tuple[mlkem.MLKEM768PrivateKey, x25519.X25519PrivateKey]:
    expanded = hashlib.shake_256(seed).digest(96)
    return (mlkem.MLKEM768PrivateKey.from_seed_bytes(expanded[:64]),          # d ‖ z (FIPS 203)
            x25519.X25519PrivateKey.from_private_bytes(expanded[64:96]))


def _raw_x(pk: x25519.X25519PublicKey) -> bytes:
    return pk.public_bytes(Encoding.Raw, PublicFormat.Raw)


class XWingPrivateKey:
    def __init__(self, seed: bytes) -> None:
        if len(seed) != SEED_LEN:
            raise MalformedMessage("semilla X-Wing de longitud inválida")
        self._seed: bytes | None = bytes(seed)
        self._m, self._x = _expand(seed)
        self._pk_x = _raw_x(self._x.public_key())
        self._pk = self._m.public_key().public_bytes_raw() + self._pk_x

    @classmethod
    def generate(cls) -> "XWingPrivateKey":
        import os
        return cls(os.urandom(SEED_LEN))

    @property
    def public_bytes(self) -> bytes:
        return self._pk

    def seed(self) -> bytes:
        if self._seed is None:
            raise AuthenticationFailure("clave X-Wing ya descartada")
        return self._seed

    @property
    def destroyed(self) -> bool:
        return self._seed is None

    def destroy(self) -> None:
        """De MEJOR ESFUERZO en Python (ver LIMITATIONS.md): deja de poder desencapsular y `destroyed` lo refleja."""
        self._seed = None
        self._m = self._x = None  # type: ignore[assignment]

    def decapsulate(self, ct: bytes) -> bytes:
        if self._seed is None:
            raise AuthenticationFailure("clave X-Wing ya descartada")
        if len(ct) != CT_LEN:
            raise MalformedMessage("texto cifrado X-Wing de longitud inválida")
        ct_m, ct_x = ct[:MLKEM_CT], ct[MLKEM_CT:]
        try:
            ss_x = self._x.exchange(x25519.X25519PublicKey.from_public_bytes(ct_x))
        except ValueError as exc:  # punto de orden pequeño / secreto compartido nulo
            raise AuthenticationFailure("componente X25519 inválido") from exc
        ss_m = self._m.decapsulate(ct_m)  # rechazo implícito (FIPS 203)
        return _combine(ss_m, ss_x, ct_x, self._pk_x)


def xwing_encapsulate(public_bytes: bytes) -> tuple[bytes, bytes]:
    """Devuelve (secreto_compartido, texto_cifrado)."""
    if len(public_bytes) != PK_LEN:
        raise MalformedMessage("clave pública X-Wing de longitud inválida")
    pk_m, pk_x = public_bytes[:MLKEM_PK], public_bytes[MLKEM_PK:]
    try:
        m_pub = mlkem.MLKEM768PublicKey.from_public_bytes(pk_m)  # comprobación de la clave de encapsulación (FIPS 203 §7.2) hecha por la biblioteca
    except ValueError as exc:
        raise MalformedMessage("clave ML-KEM inválida") from exc
    eph = x25519.X25519PrivateKey.generate()
    try:
        ss_x = eph.exchange(x25519.X25519PublicKey.from_public_bytes(pk_x))
    except ValueError as exc:
        raise AuthenticationFailure("componente X25519 inválido") from exc
    ss_m, ct_m = m_pub.encapsulate()
    ct_x = _raw_x(eph.public_key())
    return _combine(ss_m, ss_x, ct_x, pk_x), ct_m + ct_x
