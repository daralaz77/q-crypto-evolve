"""Interfaz de línea de comandos: python -m qce <comando>."""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VERSION = "0.3.0-lab"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="qce", description="Q-Crypto Evolve (laboratorio)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("test", help="batería completa (pytest)")
    sub.add_parser("scan", help="malos usos, secretos, dependencias")
    sub.add_parser("mutate", help="prueba de mutación de controles de seguridad")
    g = sub.add_parser("gates", help="puertas G1–G6 y estado")
    g.add_argument("--fast", action="store_true", help="omite mutación y auditoría de dependencias (NO promocionable)")
    sub.add_parser("demo", help="demostración: fallo → reparación → regresión → reversión")
    sub.add_parser("bench", help="mediciones de rendimiento (no son argumento de seguridad)")
    sub.add_parser("release", help="congela un snapshot verificable del código (NO lo marca estable)")
    sub.add_parser("status", help="incidentes, tareas y última evaluación")
    a = ap.parse_args(argv)

    if a.cmd == "test":
        return subprocess.call([sys.executable, "-m", "pytest"], cwd=ROOT)
    if a.cmd == "scan":
        from .security import scanners as s
        mis, sec, dep = s.scan_misuse(ROOT), s.scan_secrets(ROOT), s.audit_dependencies(ROOT)
        print(json.dumps({"misuse": [f.__dict__ for f in mis], "secrets": [f.__dict__ for f in sec], "dependencies": dep}, indent=2))
        return int(bool(mis or sec or dep["status"] != "limpia"))
    if a.cmd == "mutate":
        from .evolve.mutation import run_mutants
        r = run_mutants(ROOT)
        print(json.dumps({k: v for k, v in r.items() if k != "detail"}, indent=2))
        return int(bool(r["survivors"]))
    if a.cmd == "gates":
        from .evolve import gates
        rep = gates.evaluate(ROOT, version=VERSION, run_mutation=not a.fast, run_dep_audit=not a.fast)
        for gt in rep["gates"]:
            print(f"{gt['gate']:<20} {gt['status']:<8} {gt['detail'][:150]}")
        print(f"\nESTADO: {rep['state']}   release_id={rep['release_id']}   métricas={rep['metrics']}")
        (ROOT / "benchmarks").mkdir(exist_ok=True)
        (ROOT / "benchmarks" / "gates_latest.json").write_text(json.dumps(rep, indent=2, ensure_ascii=False))
        return 0 if rep["state"] in ("VERIFIED", "RELEASE_APPROVED") else 1
    if a.cmd == "demo":
        from .evolve import demo
        r = demo.run(ROOT, ROOT / "benchmarks")
        print("\n".join(r["log"]))
        print(f"\nDEMO {'COMPLETA' if r['all_ok'] else 'CON FALLOS'}: {sum(c['ok'] for c in r['checks'])}/{len(r['checks'])} comprobaciones · {r['timings_s']}")
        return 0 if r["all_ok"] else 1
    if a.cmd == "release":
        from .recovery import release as rel
        m = rel.build_manifest(ROOT, VERSION, {"nota": "snapshot sin aprobar"}, ["ver LIMITATIONS.md"],
                               dict(l.split("==") for l in (ROOT / "requirements.lock").read_text().split()))
        d = rel.save_release(ROOT, m)
        print(f"snapshot {m['release_id']} en {d}\nPara marcarlo ESTABLE hace falta tu aprobación explícita (rel.mark_stable).")
        return 0
    if a.cmd == "bench":
        return bench()
    if a.cmd == "status":
        from .learning.ledger import Ledger
        L = Ledger(ROOT / "learning" / "incidents.jsonl")
        for i in L.all():
            print(i["incident_id"], i.get("status"), i.get("severity"), i.get("confidence"), "—", i.get("symptom", "")[:80])
        print("patrones recurrentes:", L.patterns() or "ninguno")
        return 0
    return 2


def bench() -> int:
    from .pqc.hybrid import HybridKemPrivateKey, HybridSigPrivateKey, hybrid_encapsulate, hybrid_verify
    from .protocols.session import ClientHandshake, ServerHandshake
    ident = HybridSigPrivateKey.generate()

    def t(fn, n):
        t0 = time.perf_counter()
        for _ in range(n):
            fn()
        return round((time.perf_counter() - t0) / n * 1000, 3)

    k = HybridKemPrivateKey.generate()
    ss, ct = hybrid_encapsulate(k.public_bytes)
    sig = ident.sign(b"m", b"c")

    def hs():
        c, s = ClientHandshake(ident.public_bytes), ServerHandshake(ident)
        m3 = c.on_server_hello(s.on_client_hello(c.start()))
        m4, _ = s.on_client_finish(m3)
        c.on_server_finish(m4)

    res = {"unit": "ms/op (media)", "python": sys.version.split()[0], "kem_keygen": t(HybridKemPrivateKey.generate, 50),
           "kem_encaps": t(lambda: hybrid_encapsulate(k.public_bytes), 50), "kem_decaps": t(lambda: k.decapsulate(ct), 50),
           "sig_sign": t(lambda: ident.sign(b"m", b"c"), 30), "sig_verify": t(lambda: hybrid_verify(ident.public_bytes, b"m", sig, b"c"), 30),
           "handshake_total": t(hs, 20), "sizes_bytes": {"kem_public": 1216, "kem_ciphertext": 1120, "sig_public": 1984, "signature": 3373},
           "nota": "mediciones de rendimiento; no sustentan ninguna afirmación de seguridad"}
    (ROOT / "benchmarks").mkdir(exist_ok=True)
    (ROOT / "benchmarks" / "bench_latest.json").write_text(json.dumps(res, indent=2))
    print(json.dumps(res, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
