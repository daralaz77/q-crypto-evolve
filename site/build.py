"""Genera site/trazas.js con trazas REALES grabadas: examples/SALIDA_ESPERADA.txt (quickstart) y benchmarks/demo_latest.json (demo).
La página no inventa ni simula nada: solo muestra lo que ya ocurrió. Uso: python site/build.py"""
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def build() -> dict:
    steps: dict[int, list[str]] = {}
    final = ""
    for line in (ROOT / "examples" / "SALIDA_ESPERADA.txt").read_text(encoding="utf-8").splitlines():
        m = re.match(r"^\[(\d)\] (.*)$", line)
        if m:
            steps.setdefault(int(m.group(1)), []).append(m.group(2))
        elif line.strip():
            final = line.strip()
    demo = json.loads((ROOT / "benchmarks" / "demo_latest.json").read_text(encoding="utf-8"))
    return {
        "quickstart": {"pasos": [{"n": n, "lineas": ls} for n, ls in sorted(steps.items())], "cierre": final},
        "demo": {"todo_ok": demo["all_ok"], "comprobaciones": demo["checks"], "tiempos_s": demo["timings_s"], "no_demostrado": demo["not_demonstrated"]},
    }


if __name__ == "__main__":
    out = ROOT / "site" / "trazas.js"
    out.write_text("window.TRAZAS = " + json.dumps(build(), ensure_ascii=False, indent=1) + ";\n", encoding="utf-8")
    print("escrito", out)
