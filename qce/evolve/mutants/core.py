"""Mutantes de core (12). Archivos que rompen: qce/core/chainlog.py, qce/core/encoding.py, qce/core/openssl_ffi.py, qce/core/policy.py."""
from ._base import Mutant as M

MUTANTS = [
    M("policy-allowlist-ignored", "qce/core/policy.py", (("suite.status != \"allowed\" or suite_id not in self.allowed_suites", "suite.status != \"allowed\""),), "política"),
    M("policy-hybrid-required-off", "qce/core/policy.py", (("if \"+\" not in suite.kem or \"ML-KEM\" not in suite.kem:", "if False:"),), "KEM híbrido obligatorio"),
    M("encoding-trailing-bytes", "qce/core/encoding.py", (("if pos != len(data):", "if False:"),), "formato estricto"),
    M("encoding-length-cap", "qce/core/encoding.py", (("if ln > MAX_FIELD or pos + ln > len(data):", "if pos + ln > len(data):"),), "límite de campo"),
    M("chain-hash-check-off", "qce/core/chainlog.py", (("or not hmac.compare_digest(e[\"hash\"], _digest(n, e[\"ts\"], prev, e[\"body\"]))", ""),), "integridad del registro"),
    M("chain-anchor-off", "qce/core/chainlog.py", (("if expected_head is not None and prev != expected_head:\n            raise IntegrityError(\"la cabeza", "if False:\n            raise IntegrityError(\"la cabeza"),), "ancla externa"),
    M("chain-lock-off", "qce/core/chainlog.py", (("fcntl.flock(lk, fcntl.LOCK_EX)", "pass"),), "cadena concurrente"),
    M("san-key-name-off", "qce/core/chainlog.py", (('if _SENSITIVE_KEY.search(str(k)) and isinstance(v, (str, bytes, bytearray)):', 'if False:'),), "redacción por nombre de campo"),
    M("san-b64-short-off", "qce/core/chainlog.py", (("return len(tok) >= 22 and classes >= 2", "return len(tok) >= 40 and classes >= 2"),), "base64 corto"),
    M("san-alnum-off", "qce/core/chainlog.py", (('return bool(re.search(r"[0-9]", tok) and re.search(r"[A-Za-z]", tok)) and _entropy(tok) >= 3.5', 'return False'),), "tokens alfanuméricos"),
    M("chain-expected-head-off", "qce/core/chainlog.py", (('if expected_head is not None and prev != expected_head:  # concurrencia optimista: leer-validar-escribir atómico', 'if False:'),), "concurrencia optimista (log)"),
    M("psk-lib-version-floor-off", "qce/core/openssl_ffi.py", (('if crypto.OpenSSL_version_num() < OPENSSL_MIN:', 'if False:'),), "PSK: OpenSSL ≥ 3.5"),
]
