"""Mutación para CI sin tocar `qce/`: usa las mismas funciones de `qce.evolve.mutation`, pero con trabajadores y tiempo límite
ajustables (QCE_MUT_WORKERS, QCE_MUT_TIMEOUT) y un modo de diagnóstico del canario.

  python benchmarks/mutation_ci.py --diagnose   # N copias del canario EN PARALELO (carga real); muestra duración y salida si fallan
  python benchmarks/mutation_ci.py              # mutación completa; mismo criterio de salida que `python -m qce mutate`

Por qué existe: en el primer intento en GitHub Actions (4 vCPU, 6 trabajadores, 120 s por mutante) el arnés abortó con
«el mutante canario fue detectado». Un canario no tiene efecto, así que «detectado» = fallo por carga/tiempo, no por el mutante.
"""
import json
import os
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from qce.evolve import mutation  # noqa: E402

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


def full() -> int:
    mutation.WORKERS = WORKERS
    r = mutation.run_mutants(ROOT, timeout=TIMEOUT)
    print(json.dumps({k: v for k, v in r.items() if k != "detail"}, indent=2))
    return int(bool(r["survivors"]))


if __name__ == "__main__":
    sys.exit(diagnose() if "--diagnose" in sys.argv else full())
