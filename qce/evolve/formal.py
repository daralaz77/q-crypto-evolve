"""Verificación formal: ejecuta el modelo Tamarin de QCE1 y compara los veredictos con formal/expected.json.

Un veredicto distinto del esperado (en cualquier sentido) es un fallo: tanto un lema que deja de cumplirse como uno de los
lemas «sanidad» (que deben ser FALSOS al romper ambos componentes) que pasa a cumplirse indican que el modelo cambió.
Los mutantes del MODELO comprueban que el modelo tiene dientes: si se rompe el diseño, algún lema debe caer.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

VERDICT = re.compile(r"^  ([a-z_0-9]+) \((?:all-traces|exists-trace)\): ([a-z]+)", re.M)

# (ediciones del modelo, defines, lemas que DEBEN pasar a «falsified»)
MODEL_MUTANTS = {
    "firma_sin_ClientHello_con_ambos_KEM_rotos": (
        [("<m1, suite, ns, kpk,", "<suite, ns, kpk,"), ("<m1, suite, ~ns, kpk,", "<suite, ~ns, kpk,")],
        ["BREAKX", "BREAKM"], ["signature_binds_hello"]),
    "firma_sin_clave_KEM_efimera": (
        [("<m1, suite, ns, kpk, h(<pe, pd>)>", "<m1, suite, ns, h(<pe, pd>)>"),
         ("<m1, suite, ~ns, kpk, h(<pe, pd>)>", "<m1, suite, ~ns, h(<pe, pd>)>")],
        [], ["secrecy_c2s", "secrecy_s2c"]),
    "cliente_no_comprueba_MAC_del_servidor": (
        [("  --[ Eq(ms, mac(ck, <'server', th, mc>)),\n", "  --[ ")],
        [], ["injective_agreement"]),
}


# Mutantes del modelo QIL1 (capa interna con clave QKD): mismos criterios que MODEL_MUTANTS
QIL1_MODEL_MUTANTS = {
    "servidor_no_comprueba_etiqueta_del_cliente": (
        [("--[ Eq(tc, tag_c), ServerDone(", "--[ ServerDone(")], [], ["client_authenticated_by_qkd", "server_agreement"]),
    "cliente_no_comprueba_etiqueta_del_servidor": (
        [("--[ Eq(ts, mac(kdfc(qk, th), <'server', th>)),\n      ClientDone(", "--[ ClientDone(")], ["BREAKTLS"], ["agreement"]),
    "clave_QKD_reutilizable": (
        [("QkdS(~kid, ~qk), !QkdAll", "!QkdS(~kid, ~qk), !QkdAll"), ("QkdS(kid, qk), Fr(~ns)", "!QkdS(kid, qk), Fr(~ns)")],
        [], ["key_single_use"]),
    "clave_vuelve_a_estar_disponible_tras_completar": (
        [("ServerDone(kid, th, kdf1(qk, th), kdf2(qk, th), b, ch) ]->\n  [ ]", "ServerDone(kid, th, kdf1(qk, th), kdf2(qk, th), b, ch) ]->\n  [ QkdS(kid, qk) ]")],
        [], ["no_reuse_after_done"]),
    "claves_internas_sin_la_clave_QKD": (
        [("kdf1(qk, th)", "kdf1(th, th)"), ("kdf2(qk, th)", "kdf2(th, th)")], ["NOBIND", "BREAKTLS"], ["secrecy_c2s", "secrecy_s2c"]),
}


def available() -> bool:
    return shutil.which("tamarin-prover") is not None


def run_model(model: Path, defines: list[str], timeout: int = 600, lemmas: list[str] | None = None) -> dict[str, str]:
    """`lemmas` limita la prueba a esos lemas (los mutantes solo necesitan el que debe caer; evita lemas que con el defecto no terminan)."""
    prove = [f"--prove={l}" for l in lemmas] if lemmas else ["--prove"]
    cmd = ["tamarin-prover", str(model), *prove, *[f"-D{d}" for d in defines]]
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    return dict(VERDICT.findall(out))


def check_matrix(root: Path, workers: int = 4, model_name: str = "qce1.spthy", expected_name: str = "expected.json") -> list[str]:
    exp = json.loads((root / "formal" / expected_name).read_text(encoding="utf-8"))
    model = root / "formal" / model_name
    items = list(exp["configs"].items())
    with ThreadPoolExecutor(max_workers=workers) as pool:
        got = list(pool.map(lambda kv: run_model(model, kv[1]["defines"]), items))
    problems = []
    for (name, cfg), verdicts in zip(items, got):
        if verdicts != cfg["verdicts"]:
            diff = {k: (cfg["verdicts"].get(k), verdicts.get(k)) for k in set(cfg["verdicts"]) | set(verdicts)
                    if cfg["verdicts"].get(k) != verdicts.get(k)}
            problems.append(f"{name}: (esperado, obtenido) {diff}")
    return problems


def check_model_mutants(root: Path, model_name: str = "qce1.spthy", mutants: dict | None = None) -> list[str]:
    base = (root / "formal" / model_name).read_text(encoding="utf-8")
    problems = []
    for name, (edits, defines, must_fail) in (MODEL_MUTANTS if mutants is None else mutants).items():
        text = base
        for old, new in edits:
            if text.count(old) < 1:
                problems.append(f"{name}: fragmento obsoleto {old[:40]!r}")
                break
            text = text.replace(old, new)
        else:
            with tempfile.TemporaryDirectory() as d:
                p = Path(d) / "m.spthy"
                p.write_text(text, encoding="utf-8")
                v = run_model(p, defines, lemmas=must_fail)
            for lemma in must_fail:
                if v.get(lemma) != "falsified":
                    problems.append(f"{name}: el lema {lemma} debía caer y dio {v.get(lemma)!r} (el modelo no detecta este defecto)")
    return problems
