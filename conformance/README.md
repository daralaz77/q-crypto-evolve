# Conformidad y pruebas diferenciales (fuera del `release_id`)

Cubre lo que los vectores ACVP del proyecto **no** cubren (ver `docs/COMPARATIVA_PQC.md`, brechas B2 y B3).

```bash
python conformance/fetch_vectors.py          # descarga los vectores Wycheproof (commit fijado, SHA-256 verificado); no se guardan en git
python conformance/run_wycheproof.py         # ML-KEM-768/1024 y ML-DSA-65/87 contra cryptography/OpenSSL
python conformance/differential.py --n 25    # cryptography (OpenSSL embebido) contra el `openssl` del sistema
python -m pytest conformance/tests -o addopts= -q
```

**Dónde se guardan:** los vectores y la biblioteca compilada van a `~/.cache/qce-conformance/` (o a `QCE_CONFORMANCE_CACHE`), **fuera del repositorio**. Razón: el escáner de secretos del proyecto recorre el árbol y marcaba como «posibles secretos» 4.525 cadenas hexadecimales públicas de los vectores (G3 pasó a `blocked`); la lista de excepciones del escáner está en `qce/` y exige revisión humana, así que no la ampliamos. Los hashes fijados están en `vectors.sha256` y `mlkem-native.sha256` (formato estándar `sha256sum`, que el escáner no trata como código).

## Qué comprueba
- **Wycheproof** (C2SP, commit `d17cc89f…`): 1.587 casos. ML-KEM: ida y vuelta con rechazo implícito, claves de semilla y ciphertexts de longitud mala, claves de encapsulación con **desbordamiento de módulo** (deben rechazarse). ML-DSA: firmas inválidas de borde (hints mal codificados, norma infinita, contexto inválido, claves públicas de longitud mala).
- **Diferencial**: misma semilla ⇒ misma clave pública; encapsular con uno y desencapsular con el otro (y al revés); firmar con uno y verificar con el otro; rechazo implícito idéntico; una firma alterada la rechazan los dos.

## Segunda implementación independiente: mlkem-native
```bash
python conformance/build_mlkem_native.py                     # descarga v2.0.0 (commit fijado, SHA-256 verificado, 1,26 MB) y compila aparte
export QCE_MLKEM_NATIVE_LIB=~/.cache/qce-conformance/build/libmlkemnative-d1b2fe78.dylib   # .so en Linux
python conformance/independent.py --n 25
```
mlkem-native (PQCA; C verificado con CBMC según su proyecto, sin que yo lo reprodujera) ejecuta además lo que `cryptography` no puede: encapsulación con aleatoriedad fija (ciphertext y secreto idénticos a los vectores) y **desencapsulación con clave expandida** (`semi_expanded_decaps`, incluidas las claves con hash o clave de encapsulación embebida corruptas). Resultado: 1.077 vectores ejecutados sin fallos (los casos de longitud mala no caben en la API de tamaño fijo de C y se omiten y cuentan) y 50 rondas diferenciales contra `cryptography` sin diferencias.

## ML-DSA: firma de Wycheproof y segunda implementación independiente (mldsa-native)
```bash
python conformance/build_mldsa_native.py     # mldsa-native v2.0.0, commit 834a90d5, 1,92 MB, SHA-256 fijado; se compila aparte
python conformance/independent_dsa.py --lib ~/.cache/qce-conformance/build-mldsa/libmldsanative-834a90d5.dylib --n 25    # .so en Linux
```
- **Firma Wycheproof contra `cryptography`** (`mldsa_65/87_sign_seed_test`): 201 casos sin fallos (la clave pública derivada coincide; la firma de referencia verifica; la nuestra también; contexto largo y semilla de longitud mala se rechazan; 34 casos «solo μ» se verifican con `verify_mu`). La firma de OpenSSL es aleatorizada, así que no se compara byte a byte.
- **mldsa-native** (PQCA; verificado con CBMC según su proyecto, sin que yo lo reprodujera): verificación Wycheproof 198 (ML-DSA-65) y 229 (ML-DSA-87) casos y firma desde semilla 101 y 92 casos, todo sin fallos; **las firmas deterministas se reproducen byte a byte** con los vectores no aleatorizados (100 de 101 y 91 de 92: los dos restantes llevan la etiqueta `Randomized`). Más 50 rondas diferenciales contra `cryptography` sin diferencias.

## Autenticación ML-DSA en TLS 1.3 (brecha B1)
`python conformance/tls_mldsa_probe.py` genera una PKI ECDSA P-256 (como la del transporte actual) y otras con ML-DSA-65/87, y hace el apretón TLS 1.3 con `openssl s_server/s_client` (grupo X25519MLKEM768) y con el módulo `ssl` de Python (el que usa `qce.transport`). **Funciona con ambos**. Mensajes del servidor en un apretón con certificado hoja único: ECDSA P-256 **1.794 bytes**; ML-DSA-65 **10.155** (5,7×); ML-DSA-87 **13.431** (7,5×). Con una cadena con intermedia el tamaño casi se duplicaría. No probado: `qce.transport` con estos certificados (su `pki.py` genera ECDSA), autenticación mutua, CRL, NSS y GnuTLS.

## Límites (léelos)
- Wycheproof y las pruebas diferenciales **no** son una auditoría ni una verificación de tiempo constante.
- **`cryptography` no ejecuta `mlkem_*_semi_expanded_decaps_test`** (no importa claves de desencapsulación expandidas, solo semillas) ni compara `dk` del archivo `keygen_seed`; esos casos los cubre mlkem-native (sección anterior), no las primitivas que usa el proyecto.
- El diferencial enfrenta **dos builds de OpenSSL** (mismo linaje): detecta diferencias de versión e integración, **no** errores compartidos. La independencia real la aporta mlkem-native (sección anterior). **Solo ML-KEM**: no hay segunda implementación independiente de ML-DSA todavía.
- Los hashes de `vectors.sha256` (formato sha256sum) se calcularon al descargar por primera vez desde el commit fijado (confianza en el primer uso).
- Los «canarios» de `conformance/tests` comprueban que estos ejecutores **sí fallan** cuando un vector se altera o se ejecutan muy pocos casos.
