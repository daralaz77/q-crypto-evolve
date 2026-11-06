# Prueba diferencial ML-KEM / ML-DSA (herramienta, no forma parte de `qce/`)

Compara las primitivas poscuánticas entre implementaciones con las MISMAS semillas. Detalle, resultados y límites: `docs/PRUEBA_DIFERENCIAL_PQC.md`.

```bash
export OPENSSL_A=/ruta/a/openssl-3.6/bin/openssl OPENSSL_B=/ruta/a/openssl-4.0/bin/openssl
.venv/bin/python tools/differential/diff_pqc.py 300            # OpenSSL A, OpenSSL B y `cryptography`
python3 -m venv /tmp/pqvenv && /tmp/pqvenv/bin/pip install kyber-py dilithium-py   # SOLO en un venv aparte (no son dependencias del proyecto)
/tmp/pqvenv/bin/python tools/differential/diff_pure.py 200      # implementación independiente en Python puro
/tmp/pqvenv/bin/python tools/differential/diff_pure.py 1 control   # control negativo: DEBE reportar discrepancias
```
`diff_pure.py` necesita `kyber-py` y `dilithium-py`, que NO están en `requirements.lock`. Las semillas son deterministas y de prueba.
