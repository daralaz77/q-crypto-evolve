"""Mutación para CI sin tocar `qce/`: usa las mismas funciones de `qce.evolve.mutation`, pero con trabajadores y tiempo límite
ajustables (QCE_MUT_WORKERS, QCE_MUT_TIMEOUT) y un modo de diagnóstico del canario.

  python benchmarks/mutation_ci.py --diagnose   # N copias del canario EN PARALELO (carga real); muestra duración y salida si fallan
  python benchmarks/mutation_ci.py              # mutación completa; mismo criterio de salida que `python -m qce mutate`

Por qué existe: en el primer intento en GitHub Actions (4 vCPU, 6 trabajadores, 120 s por mutante) el arnés abortó con
«el mutante canario fue detectado». Un canario no tiene efecto, así que «detectado» = fallo por carga/tiempo, no por el mutante.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from qce.evolve import mutation  # noqa: E402

def _isolated_pytest(work: Path, timeout: int) -> subprocess.CompletedProcess:
    """Igual que `mutation._pytest` pero con un TMPDIR propio por mutante.

    Hallazgo del diagnóstico en CI: `tests/test_tls_custody.py::test_server_works_and_no_private_key_ever_sits_in_a_file` compara los
    directorios `qce-key-*` del /tmp COMPARTIDO antes y después; si otro proceso paralelo crea uno en esa ventana, la prueba falla
    sin que el código tenga nada (1 de 6 copias del canario falló así). Aislar el TMPDIR evita la carrera sin tocar `tests/`.
    """
    # FUERA del árbol del mutante: dentro, la CLI rechaza guardar claves «dentro del repositorio» (control correcto que rompía 6/6 copias).
    tmp = tempfile.mkdtemp(prefix="qce-mut-tmp-")
    try:
        return subprocess.run([sys.executable, "-B", "-m", "pytest", "-x", "-q", "-p", "no:cacheprovider"], cwd=work,
                              capture_output=True, text=True, timeout=timeout,
                              env={"PYTHONPATH": str(work), "PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1",
                                   "HYPOTHESIS_STORAGE_DIRECTORY": str(work / ".h"), "TMPDIR": tmp})
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


mutation._pytest = _isolated_pytest
WORKERS = int(os.environ.get("QCE_MUT_WORKERS", "3"))
TIMEOUT = int(os.environ.get("QCE_MUT_TIMEOUT", "900"))


def diagnose() -> int:
    canary = next(m for m in mutation.MUTANTS if m.name.startswith("CANARY"))

    def one(i: int) -> dict:
        with tempfile.TemporaryDirectory() as td:
            work = Path(td)
            mutation._sandbox(ROOT, work)
            f = work / canary.path
            src = f.read_text()
            for old, new in canary.edits:
                src = src.replace(old, new)
            f.write_text(src)
            t = time.time()
            try:
                r = mutation._pytest(work, TIMEOUT)
                return {"copia": i, "codigo": r.returncode, "segundos": round(time.time() - t, 1), "cola": (r.stdout + r.stderr)[-1200:]}
            except Exception as e:  # noqa: BLE001
                return {"copia": i, "codigo": "EXCEPCION", "segundos": round(time.time() - t, 1), "cola": repr(e)}

    with ThreadPoolExecutor(max_workers=6) as pool:
        res = list(pool.map(one, range(6)))
    for r in res:
        print(json.dumps({k: v for k, v in r.items() if k != "cola"}))
        if r["codigo"] != 0:
            print("---- salida de la copia", r["copia"], "----\n" + r["cola"])
    return int(any(r["codigo"] != 0 for r in res))


def explain(names: list[str]) -> int:
    """Aplica cada mutante SOLO y muestra qué pruebas lo detectan (o que ninguna) EN ESTE ENTORNO, más lo que ve `ssl` por defecto."""
    import ssl
    print("OpenSSL:", ssl.OPENSSL_VERSION, "| minimum_version por defecto (cliente):", ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).minimum_version)
    rc = 0
    for name in names:
        m = next(x for x in mutation.MUTANTS if x.name == name)
        with tempfile.TemporaryDirectory() as td:
            work = Path(td)
            mutation._sandbox(ROOT, work)
            f = work / m.path
            src = f.read_text()
            for old, new in m.edits:
                src = src.replace(old, new)
            f.write_text(src)
            r = mutation._pytest(work, TIMEOUT)
            print(f"=== {name}: pytest devolvió {r.returncode} ({'detectado' if r.returncode == 1 else 'SUPERVIVIENTE' if r.returncode == 0 else 'error'})")
            print((r.stdout + r.stderr)[-1500:])
            rc |= int(r.returncode == 0)
    return rc


# Supervivientes EXPLICADOS por evidencia (ejecución «explicar-tls» en CI, 2026-10-29): con el OPENSSL_CONF de qce (MinProtocol = TLSv1.3) el `ssl` de Debian 13 (OpenSSL 3.5.7)
# ya informa TLS 1.3 como mínimo aunque falte la línea `ctx.minimum_version = TLSv1_3`; la prueba `test_contexts_are_hardened` mide ese atributo y no lo distingue allí.
# El comportamiento sigue cubierto: la atestación (contextos SIN minimum_version) comprueba que un cliente limitado a TLS 1.2 no conecta, y pasa en CI.
# Se listan aparte; la puerta G3 local (macOS) los detecta y es la que cuenta para la firma.
ENV_DEPENDENT = {"tls-client-min-version-off", "tls-server-min-version-off"}


def full() -> int:
    mutation.WORKERS = WORKERS
    # Los mutantes `hsm-*` solo se detectan con el laboratorio SoftHSM + proveedor PKCS#11 (sus pruebas se SALTAN sin él, también en este contenedor):
    # evaluarlos aquí daría «supervivientes» falsos. Se excluyen de forma EXPLÍCITA y se listan; la puerta G3 local los evalúa. QCE_MUT_INCLUDE_HSM=1 los incluye.
    skipped = [] if os.environ.get("QCE_MUT_INCLUDE_HSM") else [m.name for m in mutation.MUTANTS if m.name.startswith("hsm-")]
    only = [m.name for m in mutation.MUTANTS if m.name not in skipped]
    r = mutation.run_mutants(ROOT, only=only, timeout=TIMEOUT)
    out = {k: v for k, v in r.items() if k != "detail"}
    out["no_evaluados_aqui_por_falta_del_laboratorio_hsm"] = skipped
    out["supervivientes_explicados_en_este_entorno"] = [x for x in r["survivors"] if x in ENV_DEPENDENT]
    out["supervivientes_sin_explicar"] = [x for x in r["survivors"] if x not in ENV_DEPENDENT]
    print(json.dumps(out, indent=2))
    return int(bool(out["supervivientes_sin_explicar"]))


if __name__ == "__main__":
    if "--explain" in sys.argv:
        sys.exit(explain(sys.argv[sys.argv.index("--explain") + 1].split(",")))
    sys.exit(diagnose() if "--diagnose" in sys.argv else full())
