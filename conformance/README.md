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

## Segunda implementación independiente: mlkem-native
```bash
python conformance/build_mlkem_native.py                     # descarga v2.0.0 (commit fijado, SHA-256 verificado, 1,26 MB) y compila aparte
export QCE_MLKEM_NATIVE_LIB=conformance/build/libmlkemnative-d1b2fe78.dylib   # .so en Linux
python conformance/independent.py --n 25
```
mlkem-native (PQCA; C verificado con CBMC según su proyecto, sin que yo lo reprodujera) ejecuta además lo que `cryptography` no puede: encapsulación con aleatoriedad fija (ciphertext y secreto idénticos a los vectores) y **desencapsulación con clave expandida** (`semi_expanded_decaps`, incluidas las claves con hash o clave de encapsulación embebida corruptas). Resultado: 1.077 vectores ejecutados sin fallos (los casos de longitud mala no caben en la API de tamaño fijo de C y se omiten y cuentan) y 50 rondas diferenciales contra `cryptography` sin diferencias.

## Límites (léelos)
- Wycheproof y las pruebas diferenciales **no** son una auditoría ni una verificación de tiempo constante.
- **`cryptography` no ejecuta `mlkem_*_semi_expanded_decaps_test`** (no importa claves de desencapsulación expandidas, solo semillas) ni compara `dk` del archivo `keygen_seed`; esos casos los cubre mlkem-native (sección anterior), no las primitivas que usa el proyecto.
- El diferencial enfrenta **dos builds de OpenSSL** (mismo linaje): detecta diferencias de versión e integración, **no** errores compartidos. La independencia real la aporta mlkem-native (sección anterior). **Solo ML-KEM**: no hay segunda implementación independiente de ML-DSA todavía.
- Los hashes de `vectors.manifest.json` se calcularon al descargar por primera vez desde el commit fijado (confianza en el primer uso).
- Los «canarios» de `conformance/tests` comprueban que estos ejecutores **sí fallan** cuando un vector se altera o se ejecutan muy pocos casos.
