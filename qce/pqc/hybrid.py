"""KEM híbrido X25519 + ML-KEM y firma híbrida Ed25519 + ML-DSA, en dos NIVELES de parámetros.

STANDARD = ML-KEM-768 / ML-DSA-65 (el nivel por defecto de todo el proyecto, comportamiento sin cambios).
HIGH     = ML-KEM-1024 / ML-DSA-87 (los parámetros que pide CNSA 2.0 para las partes poscuánticas). Usarlo NO convierte el sistema en conforme con CNSA 2.0:
           el híbrido sigue llevando X25519/Ed25519 y hay más requisitos (ver docs/FIPS_140_3.md).

Seguridad: el secreto combinado es seguro si AL MENOS UNO de los dos componentes lo es.
Se usan solo las primitivas estandarizadas de la biblioteca `cryptography` (FIPS 203/204);
aquí únicamente se COMPONEN. No se inventa ninguna primitiva.

El nivel NUNCA se deduce de lo que llega por la red: lo fija quien llama (en QCE1, la suite negociada y firmada en el transcript). Las longitudes se comprueban contra el nivel
esperado, y la etiqueta de derivación incluye el nivel (separación de dominios: un secreto de un nivel no coincide con el del otro aunque las entradas fueran las mismas).
"""
from __future__ import annotations

from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa, mlkem, x25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ..core.errors import AuthenticationFailure, MalformedMessage
from ..symmetric.aead import hkdf

X_LEN = 32
ED_SIG = 64


@dataclass(frozen=True)
class Level:
    name: str
    mlkem_private: type
    mlkem_public: type
    mlkem_pk: int
    mlkem_ct: int
    mldsa_private: type
    mldsa_public: type
    mldsa_pk: int
    mldsa_sig: int
    label: bytes
    mlkem_seed: int = 64   # d || z (FIPS 203)
    mldsa_seed: int = 32   # xi (FIPS 204)

    @property
    def kem_pk_len(self) -> int:
        return X_LEN + self.mlkem_pk

    @property
    def kem_ct_len(self) -> int:
        return X_LEN + self.mlkem_ct

    @property
    def sig_pk_len(self) -> int:
        return 32 + self.mldsa_pk

    @property
    def sig_len(self) -> int:
        return ED_SIG + self.mldsa_sig


STANDARD = Level("standard", mlkem.MLKEM768PrivateKey, mlkem.MLKEM768PublicKey, 1184, 1088, mldsa.MLDSA65PrivateKey, mldsa.MLDSA65PublicKey, 1952, 3309,
                 b"QCE1/hybrid-kem/X25519+ML-KEM-768")
HIGH = Level("high", mlkem.MLKEM1024PrivateKey, mlkem.MLKEM1024PublicKey, 1568, 1568, mldsa.MLDSA87PrivateKey, mldsa.MLDSA87PublicKey, 2592, 4627,
             b"QCE1/hybrid-kem/X25519+ML-KEM-1024")
LEVELS = {STANDARD.name: STANDARD, HIGH.name: HIGH}
_LABEL = STANDARD.label  # etiqueta del nivel por defecto (la tabla de constantes de docs/QCE1_SPEC.md la ancla)

# Constantes del nivel por defecto (las usan otros módulos: p. ej. la ceremonia de firma humana, que se queda en STANDARD).
MLKEM_PK, MLKEM_CT, MLKEM_SEED = STANDARD.mlkem_pk, STANDARD.mlkem_ct, STANDARD.mlkem_seed
MLDSA_PK, MLDSA_SIG, MLDSA_SEED = STANDARD.mldsa_pk, STANDARD.mldsa_sig, STANDARD.mldsa_seed
KEM_PK_LEN, KEM_CT_LEN = STANDARD.kem_pk_len, STANDARD.kem_ct_len
SIG_PK_LEN, SIG_LEN = STANDARD.sig_pk_len, STANDARD.sig_len


def _raw(pk: x25519.X25519PublicKey) -> bytes:
    return pk.public_bytes(Encoding.Raw, PublicFormat.Raw)


def _combine(ss_m: bytes, ss_x: bytes, ct: bytes, pk: bytes, level: Level = STANDARD) -> bytes:
    # Se ata el secreto a TODO el texto cifrado y a la clave pública del receptor
    # (resistencia a ataques de re-encapsulación / mix-and-match de componentes), y al nivel por la etiqueta.
    return hkdf(ss_m + ss_x, level.label + ct + pk, 32)


class HybridKemPrivateKey:
    def __init__(self, x_priv: x25519.X25519PrivateKey, m_priv, level: Level = STANDARD) -> None:
        self.level = level
        self._x, self._m = x_priv, m_priv
        self._pk = _raw(x_priv.public_key()) + m_priv.public_key().public_bytes_raw()

    @classmethod
    def generate(cls, level: Level = STANDARD) -> "HybridKemPrivateKey":
        return cls(x25519.X25519PrivateKey.generate(), level.mlkem_private.generate(), level)

    @classmethod
    def from_seed(cls, seed: bytes, level: Level = STANDARD) -> "HybridKemPrivateKey":
        if len(seed) != 32 + level.mlkem_seed:
            raise MalformedMessage("semilla híbrida de longitud inválida")
        return cls(x25519.X25519PrivateKey.from_private_bytes(seed[:32]),
                   level.mlkem_private.from_seed_bytes(seed[32:]), level)

    def seed(self) -> bytes:
        if self._x is None or self._m is None:
            raise AuthenticationFailure("clave KEM efímera ya descartada")
        from cryptography.hazmat.primitives.serialization import NoEncryption, PrivateFormat
        x = self._x.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        return x + self._m.private_bytes_raw()

    @property
    def public_bytes(self) -> bytes:
        return self._pk

    @property
    def destroyed(self) -> bool:
        return self._x is None and self._m is None

    def destroy(self) -> None:
        """Suelta las referencias a las claves privadas (X25519 y ML-KEM). Es de MEJOR ESFUERZO en Python: el intérprete puede haber copiado el secreto
        (ver LIMITATIONS.md); lo que SÍ se garantiza y se prueba es que el objeto deja de poder desencapsular y que `destroyed` lo refleja."""
        self._x = self._m = None

    def decapsulate(self, ct: bytes) -> bytes:
        if self._x is None or self._m is None:
            raise AuthenticationFailure("clave KEM efímera ya descartada")
        if len(ct) != self.level.kem_ct_len:
            raise MalformedMessage("texto cifrado KEM de longitud inválida")
        try:
            ss_x = self._x.exchange(x25519.X25519PublicKey.from_public_bytes(ct[:X_LEN]))
        except ValueError as exc:  # punto de orden pequeño / secreto compartido nulo
            raise AuthenticationFailure("componente X25519 inválido") from exc
        ss_m = self._m.decapsulate(ct[X_LEN:])  # ML-KEM usa rechazo implícito (FIPS 203)
        return _combine(ss_m, ss_x, ct, self._pk, self.level)


def hybrid_encapsulate(public_bytes: bytes, level: Level = STANDARD) -> tuple[bytes, bytes]:
    """Devuelve (secreto_compartido, texto_cifrado). El nivel lo fija quien llama; una clave de otro nivel se rechaza por su longitud."""
    if len(public_bytes) != level.kem_pk_len:
        raise MalformedMessage("clave pública KEM de longitud inválida")
    eph = x25519.X25519PrivateKey.generate()
    ss_x = eph.exchange(x25519.X25519PublicKey.from_public_bytes(public_bytes[:X_LEN]))
    m_pub = level.mlkem_public.from_public_bytes(public_bytes[X_LEN:])
    ss_m, ct_m = m_pub.encapsulate()
    ct = _raw(eph.public_key()) + ct_m
    return _combine(ss_m, ss_x, ct, public_bytes, level), ct


class HybridSigPrivateKey:
    def __init__(self, ed: ed25519.Ed25519PrivateKey, ml, level: Level = STANDARD) -> None:
        self.level = level
        self._ed, self._ml = ed, ml
        self.public_bytes = _raw_ed(ed.public_key()) + ml.public_key().public_bytes_raw()

    @classmethod
    def generate(cls, level: Level = STANDARD) -> "HybridSigPrivateKey":
        return cls(ed25519.Ed25519PrivateKey.generate(), level.mldsa_private.generate(), level)

    @classmethod
    def from_seed(cls, seed: bytes, level: Level = STANDARD) -> "HybridSigPrivateKey":
        if len(seed) != 32 + level.mldsa_seed:
            raise MalformedMessage("semilla de firma de longitud inválida")
        return cls(ed25519.Ed25519PrivateKey.from_private_bytes(seed[:32]),
                   level.mldsa_private.from_seed_bytes(seed[32:]), level)

    def seed(self) -> bytes:
        from cryptography.hazmat.primitives.serialization import NoEncryption, PrivateFormat
        return self._ed.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()) + self._ml.private_bytes_raw()

    def sign(self, message: bytes, context: bytes) -> bytes:
        if len(context) > 255:
            raise MalformedMessage("contexto demasiado largo")
        # El contexto separa dominios (handshake vs. manifiestos vs. registros).
        return self._ed.sign(context + b"\x00" + message) + self._ml.sign(message, context)


def _raw_ed(pk: ed25519.Ed25519PublicKey) -> bytes:
    return pk.public_bytes(Encoding.Raw, PublicFormat.Raw)


def hybrid_verify(public_bytes: bytes, message: bytes, signature: bytes, context: bytes, level: Level = STANDARD) -> None:
    """Ambas firmas deben ser válidas (AND). Lanza AuthenticationFailure si no. El nivel lo fija quien llama."""
    if len(public_bytes) != level.sig_pk_len or len(signature) != level.sig_len:
        raise AuthenticationFailure("longitud de clave o firma inválida")
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(public_bytes[:32]).verify(
            signature[:ED_SIG], context + b"\x00" + message)
        level.mldsa_public.from_public_bytes(public_bytes[32:]).verify(
            signature[ED_SIG:], message, context)
    except InvalidSignature as exc:
        raise AuthenticationFailure("firma híbrida inválida") from exc
