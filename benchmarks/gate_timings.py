"""Tabla de tiempos por puerta, leída de benchmarks/gates_latest.json (no ejecuta nada).

Uso: python benchmarks/gate_timings.py > benchmarks/TIEMPOS_PUERTAS.md
"""
import json
import pathlib

d = json.loads((pathlib.Path(__file__).parent / "gates_latest.json").read_text())
total = d["metrics"]["total_seconds"]
mut = next((g["evidence"]["mutation"] for g in d["gates"] if g["gate"].startswith("G3") and "mutation" in g.get("evidence", {})), None)
print(f"# Tiempos de las puertas\n\nrelease_id `{d['release_id']}`, tiempo total {total:.0f} s ({total / 60:.1f} min). Generado por `benchmarks/gate_timings.py` desde `gates_latest.json`.\n")
print("| Puerta | Segundos | % del total |\n|---|---:|---:|")
for g in d["gates"]:
    print(f"| {g['gate']} | {g['seconds']:.1f} | {100 * g['seconds'] / total:.1f} % |")
if mut:
    n = mut["total"]
    print(f"\nMutación (dentro de G3): {mut['seconds']:.0f} s para {n} mutantes ({mut['seconds'] / n:.1f} s por mutante en reloj, con 6 trabajadores en paralelo); "
          f"puntuación {mut['score']}, canario {'bien' if mut['canary_ok'] else 'MAL'}.")
    rest = total - mut["seconds"]
    print(f"Sin la mutación el resto de las puertas tarda {rest:.0f} s ({rest / 60:.1f} min).")
