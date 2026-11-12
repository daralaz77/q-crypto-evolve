#!/usr/bin/env bash
# Ciclo completo: integridad de vectores -> suite -> análisis estático -> modelo formal -> fallos controlados -> reversión.
set -u; cd "$(dirname "$0")"; T="${TMPDIR:-/tmp}"; mkdir -p "$T/semhome"
ALL="test/aead.test.mjs test/vectors.test.mjs test/mlkem-sets.test.mjs test/primitives.test.mjs test/wycheproof-more.test.mjs test/noble.test.mjs test/xwing.test.mjs"
SEM="env HOME=$T/semhome PATH=$PWD/tools/py/venv/bin:$PATH tools/py/venv/bin/semgrep scan --config tools/semgrep-crypto.yml --metrics=off --disable-version-check --no-git-ignore --quiet"
[ -f vectors/aes_gcm_test.json ] || { echo "faltan los vectores: ejecuta ./fetch-vectors.sh"; exit 1; }
echo "== 0. VECTORES íntegros =="; (cd vectors && shasum -a 256 -c SHA256SUMS.txt | grep -vc ': OK$' | sed 's/^/archivos alterados: /')
echo "== 1. SUITE =="; node --test $ALL 2>&1 | grep -E "^ℹ (tests|pass|fail|skipped)"
echo "== 2. ANÁLISIS ESTÁTICO =="
if [ -x tools/js/node_modules/.bin/eslint ]; then echo -n "ESLint security (src/): "; tools/js/node_modules/.bin/eslint --config tools/js/eslint.config.mjs src >/dev/null 2>&1 && echo "0 avisos" || echo "CON AVISOS"; else echo "ESLint: OMITIDO (npm ci --prefix tools/js)"; fi
if [ -x tools/py/venv/bin/semgrep ]; then echo -n "Semgrep reglas cripto (src/): "; $SEM src 2>&1 | grep -c '❯' | sed 's/$/ hallazgos/'
echo -n "Semgrep control positivo (muestra insegura): "; $SEM tools/semgrep-samples/bad.js 2>&1 | grep -c '❯' | sed 's/$/ hallazgos (esperado ≥5)/'; else echo "Semgrep: OMITIDO (python3 -m venv tools/py/venv && tools/py/venv/bin/pip install semgrep==1.95.0 'protobuf>=6.31' 'setuptools<81')"; fi
echo "== 3. MODELO FORMAL (Tamarin) =="
for v in "-DHYBRID" "-DCLASSICAL_ONLY" "-DPQ_ONLY"; do echo -n "variante ${v#-D}: "; (cd tools/tamarin && command -v tamarin-prover >/dev/null || { echo -n "OMITIDO (tamarin-prover no instalado)"; exit 0; }; tamarin-prover $v --prove hybrid.spthy 2>&1 | grep -E "hybrid_secrecy \(|wellformedness checks (were|failed)" | tr -s ' ' | tr '\n' ' '); echo; done
echo "== 4. FALLOS CONTROLADOS =="
M=.work; rm -rf $M; mkdir -p $M; for f in aead xwing; do cp src/$f.mjs $M/orig_$f.mjs; done
miss=0
run() { sed "$3" "$2" > "$M/$1.mjs"; cmp -s "$2" "$M/$1.mjs" && { echo "mutante $1 NO creado"; exit 1; }
  r=$(env "$4=$PWD/$M/$1.mjs" node --test $5 2>&1 | grep -E "^ℹ fail" | awk '{print $3}'); echo "mutante $1: fallos detectados = $r"; [ "${r:-0}" -gt 0 ] || miss=$((miss+1)); }
run nonce_fijo        src/aead.mjs   's/randomBytes(NONCE)/Buffer.alloc(NONCE)/'        AEAD_MODULE "test/aead.test.mjs"
run sin_verificar_tag src/aead.mjs   's/  d.setAuthTag(tag);//'                          AEAD_MODULE "test/aead.test.mjs test/vectors.test.mjs"
run ignora_aad        src/aead.mjs   's/  d.setAAD(aad);//'                              AEAD_MODULE "test/aead.test.mjs test/vectors.test.mjs"
run lista_abierta     src/aead.mjs   's/IDS.has(alg)/(IDS.has(alg) || alg in {})/'       AEAD_MODULE "test/aead.test.mjs"
run xwing_sin_label   src/xwing.mjs  's/ctX, pkX, LABEL\]/ctX, pkX]/'                    XWING_MODULE "test/xwing.test.mjs"
run xwing_sin_pkX     src/xwing.mjs  's/ssX, ctX, pkX, LABEL\]/ssX, ctX, LABEL]/'        XWING_MODULE "test/xwing.test.mjs"
run xwing_sin_ctX     src/xwing.mjs  's/ssX, ctX, pkX, LABEL\]/ssX, pkX, LABEL]/'        XWING_MODULE "test/xwing.test.mjs"
[ -x tools/py/venv/bin/semgrep ] && { echo -n "mutante sin_verificar_tag detectado ESTÁTICAMENTE por Semgrep: "; $SEM $M/sin_verificar_tag.mjs 2>&1 | grep -c 'js-tag-not-set' | sed 's/$/ hallazgo(s)/'; }
echo "== 5. REVERSIÓN =="
for f in aead xwing; do cmp src/$f.mjs $M/orig_$f.mjs || echo "src/$f.mjs ALTERADO"; done; echo "src/ sin cambios"
node --test $ALL 2>&1 | grep -E "^ℹ (tests|pass|fail)"
echo "mutantes NO detectados: $miss"
