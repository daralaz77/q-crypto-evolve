"""Interfaz de línea de comandos: python -m qce <comando>."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VERSION = "0.3.0-lab"


def _build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="qce", description="Q-Crypto Evolve (laboratorio)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("test", help="batería completa (pytest)")
    sub.add_parser("scan", help="malos usos, secretos, dependencias")
    sub.add_parser("mutate", help="prueba de mutación de controles de seguridad")
    g = sub.add_parser("gates", help="puertas G1–G6 y estado")
    g.add_argument("--fast", action="store_true", help="omite mutación y auditoría de dependencias (NO promocionable)")
    sub.add_parser("demo", help="demostración: fallo → reparación → regresión → reversión")
    sub.add_parser("formal", help="modelo formal Tamarin de QCE1: matriz de configuraciones y mutantes del modelo")
    rp = sub.add_parser("review-package", help="construye (o verifica) el paquete de revisión externa de QCE1")
    rp.add_argument("--verify", metavar="ZIP", help="verifica un paquete existente en vez de construir")
    rp.add_argument("--out", default="dist", help="carpeta de salida (por defecto dist/)")
    sc = sub.add_parser("supply-chain", help="hashes de dependencias (requirements.hashes.txt) y SBOM CycloneDX (sbom.cdx.json)")
    sc.add_argument("--check", action="store_true", help="solo comprobar la coherencia con requirements.lock (sin red)")
    sub.add_parser("tls-check", help="atestación del transporte TLS 1.3 con X25519MLKEM768 obligatorio (falla cerrado)")
    sub.add_parser("bench", help="mediciones de rendimiento (no son argumento de seguridad)")
    sub.add_parser("release", help="congela un snapshot verificable del código (NO lo marca estable)")
    sub.add_parser("status", help="incidentes, tareas y última evaluación")
    idp = sub.add_parser("identity", help="ceremonia de firma humana: crear y registrar la identidad de quien revisa o autoriza (G5/G6)")
    idsub = idp.add_subparsers(dest="idcmd", required=True)
    n = idsub.add_parser("new", help="crea la clave privada (archivo 0600 FUERA del repositorio) y muestra la pública")
    n.add_argument("name")
    n.add_argument("--dir", default="~/.qce-keys")
    r = idsub.add_parser("register", help="registra la clave pública con un rol (no aprueba nada)")
    r.add_argument("--role", required=True, choices=("reviewer", "approver"))
    r.add_argument("--identity", required=True)
    r.add_argument("--pub", required=True, help="hexadecimal o ruta de un archivo con la clave pública")
    sg = sub.add_parser("sign", help="firma una declaración sobre un código exacto (G5 reviewer / G6 approver); exige terminal interactiva")
    sg.add_argument("--role", required=True, choices=("reviewer", "approver"))
    sg.add_argument("--signer", required=True)
    sg.add_argument("--key", required=True)
    sg.add_argument("--verdict", choices=("accept", "reject"), required=True)
    sg.add_argument("--release-id", default=None)
    sg.add_argument("--notes", default="")
    return ap


def _cmd_test(a: argparse.Namespace) -> int:
    return subprocess.call([sys.executable, "-m", "pytest"], cwd=ROOT)


def _cmd_scan(a: argparse.Namespace) -> int:
    from .security import scanners as s
    mis, sec, dep = s.scan_misuse(ROOT), s.scan_secrets(ROOT), s.audit_dependencies(ROOT)
    print(json.dumps({"misuse": [f.__dict__ for f in mis], "secrets": [f.__dict__ for f in sec], "dependencies": dep}, indent=2))
    return int(bool(mis or sec or dep["status"] != "limpia"))


def _cmd_mutate(a: argparse.Namespace) -> int:
    from .evolve.mutation import run_mutants
    r = run_mutants(ROOT)
    print(json.dumps({k: v for k, v in r.items() if k != "detail"}, indent=2))
    return int(bool(r["survivors"]))


def _cmd_gates(a: argparse.Namespace) -> int:
    from .evolve import gates
    rep = gates.evaluate(ROOT, version=VERSION, run_mutation=not a.fast, run_dep_audit=not a.fast)
    for gt in rep["gates"]:
        print(f"{gt['gate']:<20} {gt['status']:<8} {gt['detail'][:150]}")
    print(f"\nESTADO: {rep['state']}   release_id={rep['release_id']}   métricas={rep['metrics']}")
    (ROOT / "benchmarks").mkdir(exist_ok=True)
    (ROOT / "benchmarks" / "gates_latest.json").write_text(json.dumps(rep, indent=2, ensure_ascii=False))
    return 0 if rep["state"] in ("VERIFIED", "RELEASE_APPROVED") else 1


def _cmd_demo(a: argparse.Namespace) -> int:
    from .evolve import demo
    r = demo.run(ROOT, ROOT / "benchmarks")
    print("\n".join(r["log"]))
    print(f"\nDEMO {'COMPLETA' if r['all_ok'] else 'CON FALLOS'}: {sum(c['ok'] for c in r['checks'])}/{len(r['checks'])} comprobaciones · {r['timings_s']}")
    return 0 if r["all_ok"] else 1


def _cmd_release(a: argparse.Namespace) -> int:
    from .recovery import release as rel
    m = rel.build_manifest(ROOT, VERSION, {"nota": "snapshot sin aprobar"}, ["ver LIMITATIONS.md"],
                           dict(l.split("==") for l in (ROOT / "requirements.lock").read_text().split()))
    d = rel.save_release(ROOT, m)
    print(f"snapshot {m['release_id']} en {d}\nPara marcarlo ESTABLE hace falta tu aprobación explícita (rel.mark_stable).")
    return 0


def _cmd_formal(a: argparse.Namespace) -> int:
    from .evolve import formal
    if not formal.available():
        print("tamarin-prover no está instalado (brew install tamarin-prover/tap/tamarin-prover): verificación formal NO ejecutada")
        return 2
    problems = (formal.check_matrix(ROOT) + formal.check_model_mutants(ROOT)
                + formal.check_matrix(ROOT, model_name="qil1.spthy", expected_name="expected_qil1.json")
                + formal.check_model_mutants(ROOT, "qil1.spthy", formal.QIL1_MODEL_MUTANTS))
    print("\n".join(problems) or "modelo formal: veredictos y mutantes del modelo conformes a formal/expected.json")
    return int(bool(problems))


def _cmd_review_package(a: argparse.Namespace) -> int:
    from .evolve import review_package as rpk
    if a.verify:
        problems = rpk.verify(Path(a.verify))
        print("\n".join(problems) or "paquete íntegro: todos los archivos coinciden con MANIFEST.sha256")
        return int(bool(problems))
    path, digest = rpk.build(ROOT, ROOT / a.out)
    print(f"{path}\nSHA-256 del zip: {digest}\n(el manifiesto NO está firmado: comunica este hash por otro canal)")
    return 0


def _cmd_supply_chain(a: argparse.Namespace) -> int:
    from .evolve import supply_chain as sc
    if a.check:
        problems = sc.check(ROOT)
        print("\n".join(problems) or "cadena de suministro coherente: lock, hashes y SBOM coinciden")
        return int(bool(problems))
    try:
        done = sc.generate(ROOT, VERSION)
    except Exception as exc:  # noqa: BLE001  (red caída, PyPI cambia, etc.: se declara, no se inventa)
        print(f"no se pudo generar (necesita red de solo lectura hacia pypi.org): {type(exc).__name__}: {exc}")
        return 2
    print("generados requirements.hashes.txt y sbom.cdx.json para:", ", ".join(done))
    return 0


def _cmd_tls_check(a: argparse.Namespace) -> int:
    from .transport import tls13  # lo primero: debe fijar OPENSSL_CONF antes de que se importe `cryptography`
    try:
        tls13.require_hybrid_only()
    except tls13.TransportMisconfigured as exc:
        print(f"TRANSPORTE NO GARANTIZADO: {exc}")
        return 2
    import ssl
    print(f"atestación OK · {ssl.OPENSSL_VERSION} · grupo único {tls13.HYBRID_GROUP} · TLS ≥ 1.3 · sin reanudación · cliente: cadena y nombre obligatorios")
    return 0


def _cmd_bench(a: argparse.Namespace) -> int:
    return bench()


def _cmd_identity(a: argparse.Namespace) -> int:
    from .evolve import ceremony
    from .core.errors import QCEError
    try:
        if a.idcmd == "new":
            path, pub = ceremony.new_identity(ROOT, Path(a.dir), a.name)
            print(f"clave privada: {path}  (permisos 0600; GUÁRDALA tú, nunca en el repositorio ni se la des a un agente)\nhuella: {ceremony.fingerprint(pub)}\nclave pública:\n{pub.hex()}")
        else:
            fp = ceremony.register(ROOT, a.role, a.identity, ceremony.parse_public(a.pub))
            print(f"registrada {a.identity!r} como {a.role} (huella {fp}). Esto NO aprueba nada; confirma la huella por otro canal y haz commit de trust/registry.json.")
        return 0
    except (QCEError, OSError) as exc:
        print(f"error: {exc}")
        return 1


def _cmd_sign(a: argparse.Namespace) -> int:
    from .evolve import ceremony
    from .core.errors import QCEError
    if not sys.stdin.isatty() and os.environ.get("QCE_ALLOW_NONINTERACTIVE_SIGN") != "1":
        print("firmar exige una terminal interactiva: una declaración humana no se automatiza")
        return 2
    try:
        rid = a.release_id or ceremony.current_release_id(ROOT)
        if sys.stdin.isatty():
            print(f"Vas a firmar como {a.signer!r} ({a.role}) el veredicto {a.verdict!r} sobre el código release_id={rid}.")
            who = a.signer
            typed = input(f"Escribe tu identidad ({who}) para confirmar: ").strip()
            if typed != who:
                print("no confirmado")
                return 2
        p = ceremony.sign(ROOT, Path(a.key), a.role, a.signer, rid, a.verdict, a.notes)
        print(f"firmado: {p}\nCualquier cambio posterior de código invalida esta firma (cambia el release_id).")
        return 0
    except (QCEError, OSError) as exc:
        print(f"error: {exc}")
        return 1


def _cmd_status(a: argparse.Namespace) -> int:
    from .learning.ledger import Ledger
    L = Ledger(ROOT / "learning" / "incidents.jsonl")
    for i in L.all():
        print(i["incident_id"], i.get("status"), i.get("severity"), i.get("confidence"), "—", i.get("symptom", "")[:80])
    print("patrones recurrentes:", L.patterns() or "ninguno")
    return 0


COMMANDS = {
    "test": _cmd_test,
    "scan": _cmd_scan,
    "mutate": _cmd_mutate,
    "gates": _cmd_gates,
    "demo": _cmd_demo,
    "release": _cmd_release,
    "formal": _cmd_formal,
    "review-package": _cmd_review_package,
    "supply-chain": _cmd_supply_chain,
    "tls-check": _cmd_tls_check,
    "bench": _cmd_bench,
    "identity": _cmd_identity,
    "sign": _cmd_sign,
    "status": _cmd_status,
}


def main(argv: list[str] | None = None) -> int:
    a = _build_parser().parse_args(argv)
    handler = COMMANDS.get(a.cmd)
    return handler(a) if handler else 2


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
