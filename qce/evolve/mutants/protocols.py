"""Mutantes de protocols (17). Archivos que rompen: qce/protocols/session.py."""
from ._base import Mutant as M

MUTANTS = [
    M("hs-server-sig-not-verified", "qce/protocols/session.py", (("hybrid_verify(self._pinned, signed, sig, CTX_SERVER, level)", "pass"),), "autenticación del servidor"),
    M("hs-suite-not-offered-allowed", "qce/protocols/session.py", (("if suite not in self._offered:", "if False:"),), "anti-degradación"),
    M("hs-transcript-unsigned", "qce/protocols/session.py",
      (("signed = _h(self._m1, suite_b,", "signed = _h(suite_b,"), ("signed = _h(m1, suite_b,", "signed = _h(suite_b,")), "firma cubre ClientHello"),
    M("hs-client-confirm-off", "qce/protocols/session.py", (("if not ct_equal(mac_c, mac(ck, b\"client\" + th)):", "if False:"),), "confirmación de clave"),
    M("hs-server-confirm-off", "qce/protocols/session.py", (("if not ct_equal(mac_s,", "if False and not ct_equal(mac_s,"),), "confirmación de clave"),
    M("hs-qkd-silent-downgrade", "qce/protocols/session.py", (("if self._qkd_key is None:", "if False:"),), "sin degradación QKD"),
    M("hs-no-forward-secrecy", "qce/protocols/session.py", (("kem, self._kem = self._kem, None  # la clave efímera se descarta pase lo que pase: secreto hacia adelante", "kem = self._kem"),), "secreto hacia adelante"),
    M("hs-direction-binding-off", "qce/protocols/session.py", (("return self.session_id + direction + aad", "return self.session_id + aad"),), "anti-reflexión",
      "las claves de cada sentido ya difieren (c2s≠s2c), así que la reflexión falla igualmente; la dirección en el AAD es defensa en profundidad"),
    M("hs-failed-state-off", "qce/protocols/session.py", (("self._state = \"failed\"  # un único intento", "self._state = \"sent_hello\"  # un único intento"),), "handshake cierra al fallar"),
    M("conf-server-mac-truncated", "qce/protocols/session.py", (('if not ct_equal(mac_c, mac(ck, b"client" + th)):', 'if not ct_equal(mac_c[:16], mac(ck, b"client" + th)[:16]):'),), "conformidad: MAC completo"),
    M("conf-client-mac-truncated", "qce/protocols/session.py", (('if not ct_equal(mac_s, mac(self._ck, b"server" + self._th + self._mac_c)):', 'if not ct_equal(mac_s[:16], mac(self._ck, b"server" + self._th + self._mac_c)[:16]):'),), "conformidad: MAC completo"),
    M("conf-fingerprint-dropped-client", "qce/protocols/session.py", (('signed = _h(self._m1, suite_b, nonce_s, kem_pk, fingerprint(self._pinned))', 'signed = _h(self._m1, suite_b, nonce_s, kem_pk)'),), "conformidad: huella en lo firmado"),
    M("conf-ct-not-in-transcript-server", "qce/protocols/session.py", (('th = _h(self._m1, self._m2, ct)\n        c2s, s2c, ck = _derive(secret, th)', 'th = _h(self._m1, self._m2)\n        c2s, s2c, ck = _derive(secret, th)'),), "conformidad: ct en el transcript"),
    M('lvl-client-verify-level-default', 'qce/protocols/session.py', (('hybrid_verify(self._pinned, signed, sig, CTX_SERVER, level)', 'hybrid_verify(self._pinned, signed, sig, CTX_SERVER)'),), 'niveles QCE1: el cliente verifica con el nivel de la suite'),
    M('lvl-client-encaps-level-default', 'qce/protocols/session.py', (('ss, ct = hybrid_encapsulate(kem_pk, level)', 'ss, ct = hybrid_encapsulate(kem_pk)'),), 'niveles QCE1: el cliente encapsula con el nivel de la suite'),
    M('lvl-server-identity-level-check-off', 'qce/protocols/session.py', (('        if self._id.level is not level:', '        if False:'),), 'niveles QCE1: el servidor no firma con una identidad de otro nivel'),
    M('lvl-server-kem-level-off', 'qce/protocols/session.py', (('self._kem = HybridKemPrivateKey.generate(level)  # efímera', 'self._kem = HybridKemPrivateKey.generate()  # efímera'),), 'niveles QCE1: la clave KEM efímera es del nivel de la suite'),
]
