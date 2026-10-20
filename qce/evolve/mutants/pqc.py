"""Mutantes de pqc (21). Archivos que rompen: qce/pqc/hybrid.py, qce/pqc/slhdsa.py."""
from ._base import Mutant as M

MUTANTS = [
    M("kem-combiner-drops-ct", "qce/pqc/hybrid.py", (("_LABEL + ct + pk", "_LABEL"),), "enlace de transcript KEM"),
    M("kem-combiner-drops-x25519", "qce/pqc/hybrid.py", (("hkdf(ss_m + ss_x,", "hkdf(ss_m,"),), "hibridación (X25519)"),
    M("kem-combiner-drops-mlkem", "qce/pqc/hybrid.py", (("hkdf(ss_m + ss_x,", "hkdf(ss_x,"),), "hibridación (ML-KEM)"),
    M("sig-ed25519-skipped", "qce/pqc/hybrid.py", (("ed25519.Ed25519PublicKey.from_public_bytes(public_bytes[:32]).verify(", "(lambda *a: None)("),), "firma híbrida AND"),
    M("sig-mldsa-skipped", "qce/pqc/hybrid.py", (("mldsa.MLDSA65PublicKey.from_public_bytes(public_bytes[32:]).verify(", "(lambda *a: None)("),), "firma híbrida AND"),
    M("sig-context-ignored", "qce/pqc/hybrid.py", (("signature[ED_SIG:], message, context)", "signature[ED_SIG:], message, b'')"),), "separación de dominios"),
    M('slh-leak-pkey-not-freed-sign', 'qce/pqc/slhdsa.py', (('            c.EVP_MD_CTX_free(mctx)\n            c.EVP_PKEY_free(pkey)\n\n\ndef slhdsa_verify', '            c.EVP_MD_CTX_free(mctx)\n\n\ndef slhdsa_verify'),), 'SLH-DSA: se libera la clave al firmar'),
    M('slh-leak-pkey-not-freed-verify', 'qce/pqc/slhdsa.py', (('        c.EVP_MD_CTX_free(mctx)\n        c.EVP_PKEY_free(pkey)\n', '        c.EVP_MD_CTX_free(mctx)\n'),), 'SLH-DSA: se libera la clave al verificar'),
    M('slh-seed-length-unchecked', 'qce/pqc/slhdsa.py', (('if not isinstance(seed, (bytes, bytearray)) or len(seed) != SEED_LEN:', 'if False:'),), 'SLH-DSA: longitud de la semilla'),
    M('slh-seed-ignored', 'qce/pqc/slhdsa.py', (('p, keep = _octets(b"seed", bytes(seed))', 'p, keep = _octets(b"seed", bytes(SEED_LEN))'),), 'SLH-DSA: la semilla se usa'),
    M('slh-seed-keygen-unchecked', 'qce/pqc/slhdsa.py', (('c.EVP_PKEY_CTX_set_params(ctx, params) != 1', 'False'),), 'SLH-DSA: la semilla se aplica'),
    M("slh-verify-accepts-zero", "qce/pqc/slhdsa.py", (("if c.EVP_DigestVerify(mctx, s, len(sig), msg, len(message)) != 1:", "if c.EVP_DigestVerify(mctx, s, len(sig), msg, len(message)) < 0:"),), "SLH-DSA: solo 1 es válida"),
    M("slh-verify-length-off", "qce/pqc/slhdsa.py", (("    if len(pk) != PK_LEN or len(sig) != SIG_LEN:\n        raise MalformedMessage", "    if False:\n        raise MalformedMessage"),), "SLH-DSA: longitudes en la verificación"),
    M("slh-context-ignored-sign", "qce/pqc/slhdsa.py", (("    if context:\n        p, b = _octets(b\"context-string\"", "    if False:\n        p, b = _octets(b\"context-string\""),), "SLH-DSA: contexto en la firma"),
    M("slh-context-limit-off", "qce/pqc/slhdsa.py", (("len(context) > CONTEXT_MAX:", "False:"),), "SLH-DSA: límite de contexto"),
    M("slh-context-limit-boundary", "qce/pqc/slhdsa.py", (("len(context) > CONTEXT_MAX:", "len(context) >= CONTEXT_MAX:"),), "SLH-DSA: límite de contexto inclusivo"),
    M("slh-deterministic-ignored", "qce/pqc/slhdsa.py", (("    if deterministic:\n        det = ctypes.c_int(1)", "    if False:\n        det = ctypes.c_int(1)"),), "SLH-DSA: modo determinista"),
    M("slh-sign-length-unchecked", "qce/pqc/slhdsa.py", (("c.EVP_DigestSign(mctx, sig, ctypes.byref(n), msg, len(message)) != 1 or n.value != expected", "c.EVP_DigestSign(mctx, sig, ctypes.byref(n), msg, len(message)) != 1"),), "SLH-DSA: longitud de la firma producida"),
    M("slh-from-bytes-length-off", "qce/pqc/slhdsa.py", (("        if len(sk) != SK_LEN:\n            raise MalformedMessage", "        if False:\n            raise MalformedMessage"),), "SLH-DSA: longitud de la clave privada"),
    M("slh-public-part-wrong", "qce/pqc/slhdsa.py", (("return cls(sk, bytes(sk[PK_LEN:]))", "return cls(sk, bytes(sk[:PK_LEN]))"),), "SLH-DSA: parte pública de la privada"),
    M("slh-export-length-unchecked", "qce/pqc/slhdsa.py", (("or n.value != size:", ":"),), "SLH-DSA: longitud al exportar"),
]
