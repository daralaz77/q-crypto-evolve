"""KEM híbrido X25519 + ML-KEM-768 y firma híbrida Ed25519 + ML-DSA-65.

Seguridad: el secreto combinado es seguro si AL MENOS UNO de los dos componentes lo es.
Se usan solo las primitivas estandarizadas de la biblioteca `cryptography` (FIPS 203/204);
aquí únicamente se COMPONEN. No se inventa ninguna primitiva.
"""
from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa, mlkem, x25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ..core.errors import AuthenticationFailure, MalformedMessage
from ..symmetric.aead import hkdf

X_LEN = 32
MLKEM_PK, MLKEM_CT, MLKEM_SEED = 1184, 1088, 64
MLDSA_PK, MLDSA_SIG, MLDSA_SEED = 1952, 3309, 32
ED_SIG = 64
KEM_PK_LEN = X_LEN + MLKEM_PK
KEM_CT_LEN = X_LEN + MLKEM_CT
SIG_PK_LEN = 32 + MLDSA_PK
SIG_LEN = ED_SIG + MLDSA_SIG

_LABEL = b"QCE1/hybrid-kem/X25519+ML-KEM-768"


def _raw(pk: x25519.X25519PublicKey) -> bytes:
    return pk.public_bytes(Encoding.Raw, PublicFormat.Raw)


def _combine(ss_m: bytes, ss_x: bytes, ct: bytes, pk: bytes) -> bytes:
    # Se ata el secreto a TODO el texto cifrado y a la clave pública del receptor
    # (resistencia a ataques de re-encapsulación / mix-and-match de componentes).
    return hkdf(ss_m + ss_x, _LABEL + ct + pk, 32)


class HybridKemPrivateKey:
    def __init__(self, x_priv: x25519.X25519PrivateKey, m_priv: mlkem.MLKEM768PrivateKey) -> None:
        self._x, self._m = x_priv, m_priv
        self._pk = _raw(x_priv.public_key()) + m_priv.public_key().public_bytes_raw()

    @classmethod
    def generate(cls) -> "HybridKemPrivateKey":
        return cls(x25519.X25519PrivateKey.generate(), mlkem.MLKEM768PrivateKey.generate())

    @classmethod
    def from_seed(cls, seed: bytes) -> "HybridKemPrivateKey":
        if len(seed) != 32 + MLKEM_SEED:
            raise MalformedMessage("semilla híbrida de longitud inválida")
        return cls(x25519.X25519PrivateKey.from_private_bytes(seed[:32]),
                   mlkem.MLKEM768PrivateKey.from_seed_bytes(seed[32:]))

    def seed(self) -> bytes:
        from cryptography.hazmat.primitives.serialization import NoEncryption, PrivateFormat
        x = self._x.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        return x + self._m.private_bytes_raw()

    @property
    def public_bytes(self) -> bytes:
        return self._pk

    def decapsulate(self, ct: bytes) -> bytes:
        if len(ct) != KEM_CT_LEN:
            raise MalformedMessage("texto cifrado KEM de longitud inválida")
        ss_x = self._x.exchange(x25519.X25519PublicKey.from_public_bytes(ct[:X_LEN]))
        ss_m = self._m.decapsulate(ct[X_LEN:])  # ML-KEM usa rechazo implícito (FIPS 203)
        return _combine(ss_m, ss_x, ct, self._pk)


def hybrid_encapsulate(public_bytes: bytes) -> tuple[bytes, bytes]:
    """Devuelve (secreto_compartido, texto_cifrado)."""
    if len(public_bytes) != KEM_PK_LEN:
        raise MalformedMessage("clave pública KEM de longitud inválida")
    eph = x25519.X25519PrivateKey.generate()
    ss_x = eph.exchange(x25519.X25519PublicKey.from_public_bytes(public_bytes[:X_LEN]))
    m_pub = mlkem.MLKEM768PublicKey.from_public_bytes(public_bytes[X_LEN:])
    ss_m, ct_m = m_pub.encapsulate()
    ct = _raw(eph.public_key()) + ct_m
    return _combine(ss_m, ss_x, ct, public_bytes), ct


class HybridSigPrivateKey:
    def __init__(self, ed: ed25519.Ed25519PrivateKey, ml: mldsa.MLDSA65PrivateKey) -> None:
        self._ed, self._ml = ed, ml
        self.public_bytes = _raw_ed(ed.public_key()) + ml.public_key().public_bytes_raw()

    @classmethod
    def generate(cls) -> "HybridSigPrivateKey":
        return cls(ed25519.Ed25519PrivateKey.generate(), mldsa.MLDSA65PrivateKey.generate())

    @classmethod
    def from_seed(cls, seed: bytes) -> "HybridSigPrivateKey":
        if len(seed) != 32 + MLDSA_SEED:
            raise MalformedMessage("semilla de firma de longitud inválida")
        return cls(ed25519.Ed25519PrivateKey.from_private_bytes(seed[:32]),
                   mldsa.MLDSA65PrivateKey.from_seed_bytes(seed[32:]))

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


def hybrid_verify(public_bytes: bytes, message: bytes, signature: bytes, context: bytes) -> None:
    """Ambas firmas deben ser válidas (AND). Lanza AuthenticationFailure si no."""
    if len(public_bytes) != SIG_PK_LEN or len(signature) != SIG_LEN:
        raise AuthenticationFailure("longitud de clave o firma inválida")
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(public_bytes[:32]).verify(
            signature[:ED_SIG], context + b"\x00" + message)
        mldsa.MLDSA65PublicKey.from_public_bytes(public_bytes[32:]).verify(
            signature[ED_SIG:], message, context)
    except InvalidSignature as exc:
        raise AuthenticationFailure("firma híbrida inválida") from exc
