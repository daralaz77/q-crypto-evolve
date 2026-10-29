# Conformidad y pruebas diferenciales (fuera del `release_id`)

Cubre lo que los vectores ACVP del proyecto **no** cubren (ver `docs/COMPARATIVA_PQC.md`, brechas B2 y B3).

```bash
python conformance/fetch_vectors.py          # descarga los vectores Wycheproof (commit fijado, SHA-256 verificado); no se guardan en git
python conformance/run_wycheproof.py         # ML-KEM-768/1024 y ML-DSA-65/87 contra cryptography/OpenSSL
python conformance/differential.py --n 25    # cryptography (OpenSSL embebido) contra el `openssl` del sistema
python -m pytest conformance/tests -o addopts= -q
```

## Qué comprueba
- **Wycheproof** (C2SP, commit `d17cc89f…`): 1.587 casos. ML-KEM: ida y vuelta con rechazo implícito, claves de semilla y ciphertexts de longitud mala, claves de encapsulación con **desbordamiento de módulo** (deben rechazarse). ML-DSA: firmas inválidas de borde (hints mal codificados, norma infinita, contexto inválido, claves públicas de longitud mala).
- **Diferencial**: misma semilla ⇒ misma clave pública; encapsular con uno y desencapsular con el otro (y al revés); firmar con uno y verificar con el otro; rechazo implícito idéntico; una firma alterada la rechazan los dos.

## Límites (léelos)
- Wycheproof y las pruebas diferenciales **no** son una auditoría ni una verificación de tiempo constante.
- **`mlkem_*_semi_expanded_decaps_test` no se ejecuta**: la API de `cryptography` no importa claves de desencapsulación expandidas (solo semillas). Tampoco se compara `dk` del archivo `keygen_seed`.
- El diferencial enfrenta **dos builds de OpenSSL** (mismo linaje): detecta diferencias de versión e integración, **no** errores compartidos. Una implementación realmente independiente (mlkem-native, liboqs, libcrux) exige descargar código; está pendiente de tu visto bueno.
- Los hashes de `vectors.manifest.json` se calcularon al descargar por primera vez desde el commit fijado (confianza en el primer uso).
- Los «canarios» de `conformance/tests` comprueban que estos ejecutores **sí fallan** cuando un vector se altera o se ejecutan muy pocos casos.
