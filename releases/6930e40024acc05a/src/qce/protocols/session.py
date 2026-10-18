"""Handshake autenticado de 2 vueltas con secreto hacia adelante y registro cifrado.

C→S ClientHello  [versión, nonce_c, suites, qkd_key_id]
S→C ServerHello  [suite, nonce_s, kem_pk_efímera, firma_servidor]
C→S ClientFinish [kem_ct, mac_cliente]
S→C ServerFinish [mac_servidor]

- El servidor firma (ML-DSA-65 + Ed25519) el transcript completo del ClientHello: un atacante
  activo no puede rebajar la lista de suites sin invalidar la firma (anti-degradación).
- La clave KEM es efímera: comprometer la identidad a largo plazo no revela sesiones pasadas.
- Una clave QKD opcional se mezcla (HKDF) con el secreto poscuántico; nunca lo sustituye.
- Si el cliente declara QKD y el servidor no la tiene, se aborta: no hay degradación silenciosa.
"""
from __future__ import annotations

import hashlib
import os
from typing import Callable

from ..core.encoding import pack, unpack
from ..core.errors import AuthenticationFailure, MalformedMessage, PolicyViolation
from ..core.policy import Policy
from ..pqc.hybrid import (HybridKemPrivateKey, HybridSigPrivateKey, hybrid_encapsulate,
                          hybrid_verify)
from ..symmetric.aead import OpeningKey, SealingKey, ct_equal, hkdf, mac

VERSION = b"QCE1"
T_CH, T_SH, T_CF, T_SF, T_REC = 0x01, 0x02, 0x03, 0x04, 0x10
CTX_SERVER = b"QCE1/server-hello"


def _h(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for p in parts:
        h.update(len(p).to_bytes(4, "big") + p)
    return h.digest()


def fingerprint(identity_pk: bytes) -> bytes:
    return hashlib.sha256(identity_pk).digest()


class Session:
    """Capa de registros: claves de un solo sentido, contador como nonce, ventana anti-repetición."""

    def __init__(self, aead: str, send: tuple[bytes, bytes], recv: tuple[bytes, bytes],
                 session_id: bytes, direction_out: bytes, direction_in: bytes, policy: Policy) -> None:
        self._out = SealingKey(aead, send[0], send[1], policy.max_records_per_key)
        self._in = OpeningKey(aead, recv[0], recv[1], policy.replay_window)
        self.session_id, self._d_out, self._d_in = session_id, direction_out, direction_in

    def seal(self, plaintext: bytes, aad: bytes = b"") -> bytes:
        seq, ct = self._out.seal(plaintext, self._aad(self._d_out, aad))
        return pack(T_REC, [seq.to_bytes(8, "big"), ct])

    def open(self, record: bytes, aad: bytes = b"") -> bytes:
        seq_b, ct = unpack(record, T_REC, 2)
        if len(seq_b) != 8:
            raise MalformedMessage("secuencia inválida")
        return self._in.open(int.from_bytes(seq_b, "big"), ct, self._aad(self._d_in, aad))

    def _aad(self, direction: bytes, aad: bytes) -> bytes:
        return self.session_id + direction + aad


def _derive(secret: bytes, th: bytes):
    okm = hkdf(secret, b"QCE1/keys" + th, 32 * 3 + 8, salt=th)
    return (okm[0:32], okm[96:100]), (okm[32:64], okm[100:104]), okm[64:96]


class ClientHandshake:
    def __init__(self, server_identity_pk: bytes, policy: Policy | None = None,
                 offered: list[str] | None = None, qkd: tuple[bytes, bytes] | None = None) -> None:
        self.policy = policy or Policy()
        self._pinned = server_identity_pk
        self._offered = offered or list(self.policy.allowed_suites)
        self._qkd = qkd  # (key_id, key)
        self._m1 = b""
        self._state = "new"

    def start(self) -> bytes:
        self._nonce = os.urandom(32)
        qid = self._qkd[0] if self._qkd else b""
        self._m1 = pack(T_CH, [VERSION, self._nonce, ",".join(self._offered).encode(), qid])
        self._state = "sent_hello"
        return self._m1

    def on_server_hello(self, m2: bytes) -> bytes:
        if self._state != "sent_hello":
            raise PolicyViolation("mensaje fuera de orden")
        suite_b, nonce_s, kem_pk, sig = unpack(m2, T_SH, 4)
        suite = suite_b.decode("ascii", "replace")
        if suite not in self._offered:  # el servidor no puede elegir algo que no ofrecimos
            raise PolicyViolation("el servidor eligió una suite no ofrecida")
        self.suite = self.policy.check_suite(suite)
        signed = _h(self._m1, suite_b, nonce_s, kem_pk, fingerprint(self._pinned))
        hybrid_verify(self._pinned, signed, sig, CTX_SERVER)  # autentica al servidor + transcript
        ss, ct = hybrid_encapsulate(kem_pk)
        secret = ss + (self._qkd[1] if self._qkd else b"")
        self._th = _h(self._m1, m2, ct)
        self._send, self._recv, self._ck = _derive(secret, self._th)
        self._mac_c = mac(self._ck, b"client" + self._th)
        self._state = "sent_finish"
        return pack(T_CF, [ct, self._mac_c])

    def on_server_finish(self, m4: bytes) -> Session:
        if self._state != "sent_finish":
            raise PolicyViolation("mensaje fuera de orden")
        (mac_s,) = unpack(m4, T_SF, 1)
        if not ct_equal(mac_s, mac(self._ck, b"server" + self._th + self._mac_c)):
            raise AuthenticationFailure("confirmación de clave del servidor inválida")
        self._state = "done"
        return Session(self.suite.aead, self._send, self._recv, self._th[:16], b"c", b"s", self.policy)


class ServerHandshake:
    def __init__(self, identity: HybridSigPrivateKey, policy: Policy | None = None,
                 qkd_lookup: Callable[[bytes], bytes | None] | None = None) -> None:
        self._id = identity
        self.policy = policy or Policy()
        self._qkd_lookup = qkd_lookup or (lambda _id: None)
        self._state = "new"

    def on_client_hello(self, m1: bytes) -> bytes:
        if self._state != "new":
            raise PolicyViolation("handshake ya iniciado")
        version, nonce_c, suites_b, qid = unpack(m1, T_CH, 4)
        if version != VERSION or len(nonce_c) != 32:
            raise MalformedMessage("versión o nonce inválidos")
        offered = suites_b.decode("ascii", "replace").split(",")
        if len(offered) > 8:
            raise MalformedMessage("demasiadas suites")
        suite_id = self.policy.select(offered)
        self.suite = self.policy.check_suite(suite_id)
        self._qkd_key = None
        if qid:
            self._qkd_key = self._qkd_lookup(qid)
            if self._qkd_key is None:
                raise PolicyViolation("QKD declarada por el cliente pero ausente: se aborta, no se degrada")
        self._kem = HybridKemPrivateKey.generate()  # efímera
        nonce_s, suite_b = os.urandom(32), suite_id.encode()
        signed = _h(m1, suite_b, nonce_s, self._kem.public_bytes, fingerprint(self._id.public_bytes))
        sig = self._id.sign(signed, CTX_SERVER)
        self._m1, self._state = m1, "sent_hello"
        self._m2 = pack(T_SH, [suite_b, nonce_s, self._kem.public_bytes, sig])
        return self._m2

    def on_client_finish(self, m3: bytes) -> tuple[bytes, Session]:
        if self._state != "sent_hello":
            raise PolicyViolation("mensaje fuera de orden")
        ct, mac_c = unpack(m3, T_CF, 2)
        ss = self._kem.decapsulate(ct)
        self._kem = None  # la clave efímera se descarta: secreto hacia adelante
        secret = ss + (self._qkd_key or b"")
        th = _h(self._m1, self._m2, ct)
        c2s, s2c, ck = _derive(secret, th)
        if not ct_equal(mac_c, mac(ck, b"client" + th)):
            raise AuthenticationFailure("confirmación de clave del cliente inválida")
        self._state = "done"
        m4 = pack(T_SF, [mac(ck, b"server" + th + mac_c)])
        return m4, Session(self.suite.aead, s2c, c2s, th[:16], b"s", b"c", self.policy)
