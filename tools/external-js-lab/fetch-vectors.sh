#!/usr/bin/env bash
# Descarga los vectores oficiales (no se redistribuyen en el repo) y verifica su SHA-256 contra vectors/SHA256SUMS.txt.
# Fuentes: C2SP/wycheproof (testvectors_v1), usnistgov/ACVP-Server (gen-val/json-files), dconnolly/draft-connolly-cfrg-xwing-kem (spec).
set -euo pipefail; cd "$(dirname "$0")/vectors"; mkdir -p nist
W=https://raw.githubusercontent.com/C2SP/wycheproof/main/testvectors_v1
N=https://raw.githubusercontent.com/usnistgov/ACVP-Server/master/gen-val/json-files
for f in aes_gcm_test chacha20_poly1305_test x25519_test mlkem_{512,768,1024}_{test,keygen_seed_test,semi_expanded_decaps_test,encaps_test}; do
  [ -s "$f.json" ] || curl -sSfL -m 60 -o "$f.json" "$W/$f.json"; done
for d in ML-KEM-encapDecap-FIPS203 ML-KEM-keyGen-FIPS203; do for k in prompt expectedResults; do
  [ -s "nist/$d-$k.json" ] || curl -sSfL -m 90 -o "nist/$d-$k.json" "$N/$d/$k.json"; done; done
[ -s xwing_test-vectors.json ] || curl -sSfL -m 30 -o xwing_test-vectors.json https://raw.githubusercontent.com/dconnolly/draft-connolly-cfrg-xwing-kem/main/spec/test-vectors.json
shasum -a 256 -c SHA256SUMS.txt | grep -v ': OK$' && { echo "HASH DISTINTO: los vectores upstream cambiaron o la descarga está alterada"; exit 1; } || echo "vectores verificados ($(wc -l < SHA256SUMS.txt) archivos)"
