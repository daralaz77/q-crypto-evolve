# Uso: examples/probar_con_curl.sh <carpeta-de-qce-kme>  (la carpeta donde dejó kme.out y pki/; ver README)
set -u
D=$1; PORT=$(grep -o "127.0.0.1:[0-9]*" $D/kme.out | head -1 | cut -d: -f2); P=$D/pki
M="--cacert $P/ca.pem --cert $P/cli-sae-master.pem --key $P/cli-sae-master.key --resolve kme.lab:$PORT:127.0.0.1"
S="--cacert $P/ca.pem --cert $P/cli-sae-slave.pem --key $P/cli-sae-slave.key --resolve kme.lab:$PORT:127.0.0.1"
U=https://kme.lab:$PORT/api/v1/keys
echo "== status (maestra)"; curl -s $M $U/sae-slave/status; echo
echo "== enc_keys (maestra)"; OUT=$(curl -s $M "$U/sae-slave/enc_keys?number=1&size=256"); echo "$OUT" | head -c 200; echo
KID=$(echo "$OUT" | python3 -c "import sys,json;print(json.load(sys.stdin)['keys'][0]['key_ID'])"); echo KID=$KID
echo "== dec_keys (esclava)"; curl -s $S "$U/sae-master/dec_keys?key_ID=$KID" | head -c 200; echo
echo "== dec_keys otra vez (esclava)"; curl -s $S "$U/sae-master/dec_keys?key_ID=$KID"; echo
echo "== maestra intenta recoger"; curl -s -w ' [HTTP %{http_code}]' $M "$U/sae-slave/dec_keys?key_ID=$KID"; echo
