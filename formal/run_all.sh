#!/bin/sh
# Ejecuta el modelo en cada configuración y imprime "config|lema|veredicto". Uso: ./run_all.sh
cd "$(dirname "$0")" || exit 1
run() {
  name="$1"; shift
  out=$(tamarin-prover qce1.spthy --prove "$@" 2>&1)
  echo "$out" | grep -E "^  [a-z_0-9]+ \((all-traces|exists-trace)\): " | sed -E "s/^  ([a-z_0-9]+) \((all-traces|exists-trace)\): ([a-z]+).*/$name|\1|\2|\3/"
}
run base
run breakX -DBREAKX
run breakM -DBREAKM
run breakE -DBREAKE
run breakD -DBREAKD
run breakXM -DBREAKX -DBREAKM
run breakED -DBREAKE -DBREAKD
run breakXE -DBREAKX -DBREAKE
run breakMD -DBREAKM -DBREAKD
run qkd -DQKD
run qkd_breakXM -DQKD -DBREAKX -DBREAKM
