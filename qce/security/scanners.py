"""Detección de secretos, malos usos criptográficos (AST) y auditoría de dependencias."""
from __future__ import annotations

import ast
import json
import math
import re
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

SKIP_DIRS = {".venv", ".git", "__pycache__", ".pytest_cache", ".hypothesis", "releases"}


@dataclass(frozen=True)
class Finding:
    rule: str
    path: str
    line: int
    detail: str
    severity: str  # critica | alta | media | baja


def _files(root: Path, suffixes: tuple[str, ...]):
    for p in sorted(root.rglob("*")):
        # SKIP_DIRS solo se aplica al primer nivel: un directorio 'releases' dentro de qce/ SÍ se escanea
        if p.is_file() and p.suffix in suffixes and p.relative_to(root).parts[0] not in SKIP_DIRS \
                and "__pycache__" not in p.parts:
            yield p


# ---- secretos -------------------------------------------------------------------------
_PATTERNS = {
    "pem-private-key": re.compile(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----"),
    "aws-access-key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "generic-secret-assign": re.compile(r"(?i)\b(?:password|passwd|secret|api[_-]?key|token)\b\s*[:=]\s*['\"][^'\"\s]{12,}['\"]"),
    "long-hex-literal": re.compile(r"['\"][0-9a-fA-F]{64,}['\"]"),
}


def _entropy(s: str) -> float:
    c = Counter(s)
    return -sum(n / len(s) * math.log2(n / len(s)) for n in c.values())


# Excepciones EXPLÍCITAS (prefijo de ruta, regla) → motivo. Añadir una requiere revisión humana (nivel 3).
SECRET_ALLOW = {
    ("tests/vectors/", "secret:long-hex-literal"): "vectores de prueba públicos de NIST ACVP",
    ("tests/vectors/", "secret:high-entropy"): "vectores de prueba públicos de NIST ACVP",
    ("learning/", "secret:long-hex-literal"): "hashes SHA-256 de la cadena de registro (no son secretos)",
    ("tests/test_keys_qkd_log.py", "secret:pem-private-key"): "literal falso para probar la redacción de PEM",
    ("tests/test_audit_findings.py", "secret:generic-secret-assign"): "secreto FALSO plantado para probar el escáner",
    ("tests/test_tooling.py", "secret:pem-private-key"): "secreto FALSO plantado para probar el escáner",
    ("tests/test_tooling.py", "secret:generic-secret-assign"): "secreto FALSO plantado para probar el escáner",
    ("trust/", "secret:long-hex-literal"): "claves PÚBLICAS de revisores/aprobadores",
    ("sbom.cdx.json", "secret:long-hex-literal"): "hashes SHA-256 PÚBLICOS de archivos publicados en PyPI (SBOM); autorizada por el usuario el 2026-10-20",
    ("reviews/", "secret:long-hex-literal"): "firmas públicas de declaraciones de revisión",
    ("benchmarks/", "secret:long-hex-literal"): "informes generados (hashes de release)",
}


def scan_secrets(root: Path) -> list[Finding]:
    out: list[Finding] = []
    for p in _files(root, (".py", ".md", ".json", ".jsonl", ".txt", ".toml", ".ini", ".env", ".yml", ".yaml", ".pem", ".key", ".cfg", ".conf")):
        rel = str(p.relative_to(root))
        for n, line in enumerate(p.read_text(errors="replace").splitlines(), 1):
            for rule, rx in _PATTERNS.items():
                if rx.search(line):
                    out.append(Finding(f"secret:{rule}", rel, n, "posible secreto (valor omitido)", "critica"))
            for tok in re.findall(r"['\"]([A-Za-z0-9+/_=-]{40,})['\"]", line):
                if _entropy(tok) > 4.3:
                    out.append(Finding("secret:high-entropy", rel, n, "cadena de alta entropía (valor omitido)", "alta"))
    return [f for f in out if not any(f.path.startswith(pre) and f.rule == r for (pre, r) in SECRET_ALLOW)]


# ---- malos usos (AST) ------------------------------------------------------------------
# Excepciones EXPLÍCITAS y justificadas. Añadir una requiere revisión humana (nivel 2).
ALLOW = {
    ("qce/qkd/adapter.py", "weak-random-import"):
        "random solo genera el ruido de la SIMULACIÓN de QBER; las claves usan os.urandom",
}
_MAC_NAMES = re.compile(r"(?i)(mac|tag|sig|signature|digest|token)")


class _Visitor(ast.NodeVisitor):
    def __init__(self, rel: str) -> None:
        self.rel, self.out = rel, []

    def add(self, rule, node, detail, sev):
        self.out.append(Finding(rule, self.rel, node.lineno, detail, sev))

    def visit_Import(self, node):
        for a in node.names:
            if a.name == "random":
                self.add("weak-random-import", node, "módulo random no es criptográfico", "alta")
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.module == "random":
            self.add("weak-random-import", node, "from random import …", "alta")
        if node.module == "hashlib" and any(a.name in ("md5", "sha1") for a in node.names):
            self.add("weak-hash", node, "from hashlib import md5/sha1", "alta")
        if node.module in ("pickle", "marshal"):
            self.add("unsafe-deserialization", node, f"from {node.module} import …", "critica")
        self.generic_visit(node)

    def visit_Call(self, node):
        name = ast.unparse(node.func)
        if name in ("hashlib.md5", "hashlib.sha1", "md5", "sha1") or name.endswith(".MD5") or name.endswith(".SHA1"):
            self.add("weak-hash", node, f"{name} no admitido", "alta")
        if "ECB" in name:
            self.add("ecb-mode", node, "modo ECB", "critica")
        if name in ("eval", "exec", "pickle.loads", "pickle.load"):
            self.add("unsafe-deserialization", node, name, "critica")
        for kw in node.keywords:
            if kw.arg in ("verify", "check_hostname") and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                self.add("disabled-validation", node, f"{kw.arg}=False", "critica")
        if name in ("print",) and any(_MAC_NAMES.search(ast.unparse(a)) and "key" in ast.unparse(a).lower() for a in node.args):
            self.add("secret-print", node, "posible impresión de clave", "alta")
        self.generic_visit(node)

    def visit_Assert(self, node):
        # `assert` desaparece con python -O: nunca como control de seguridad.
        self.add("assert-in-library", node, "assert no es un control de seguridad", "media")

    def visit_Compare(self, node):
        if any(isinstance(op, (ast.Eq, ast.NotEq)) for op in node.ops):
            text = ast.unparse(node)
            if any(_MAC_NAMES.search(ast.unparse(x)) for x in [node.left, *node.comparators]) and \
                    not any(isinstance(x, ast.Constant) for x in [node.left, *node.comparators]) and \
                    "len(" not in text:
                self.add("non-constant-time-compare", node, text[:60], "alta")
        self.generic_visit(node)


def scan_misuse(root: Path, package: str = "qce") -> list[Finding]:
    out: list[Finding] = []
    for p in _files(root, (".py",)):
        rel = str(p.relative_to(root))
        if not rel.startswith(package + "/"):
            continue
        v = _Visitor(rel)
        v.visit(ast.parse(p.read_text(), filename=rel))
        out += [f for f in v.out if (f.path, f.rule) not in ALLOW]
    return out


# ---- dependencias ------------------------------------------------------------------------
def audit_dependencies(root: Path) -> dict:
    """pip-audit contra la base OSV/PyPI. Requiere red; si falta, se declara 'no ejecutada'."""
    req = root / "requirements.lock"
    if not req.exists():
        return {"status": "no_ejecutada", "reason": "falta requirements.lock"}
    try:
        r = subprocess.run([sys.executable, "-m", "pip_audit", "-r", str(req), "--format", "json", "--no-deps",
                            "--disable-pip", "--progress-spinner", "off"],
                           capture_output=True, text=True, timeout=180)
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        return {"status": "no_ejecutada", "reason": type(exc).__name__}
    try:
        data = json.loads(r.stdout)
    except json.JSONDecodeError:
        return {"status": "no_ejecutada", "reason": (r.stderr or "salida no JSON")[-200:]}
    vulns = [{"package": d["name"], "version": d["version"], "ids": [v["id"] for v in d["vulns"]]}
             for d in data.get("dependencies", []) if d.get("vulns")]
    return {"status": "vulnerable" if vulns else "limpia", "vulnerabilities": vulns,
            "checked": len(data.get("dependencies", []))}
