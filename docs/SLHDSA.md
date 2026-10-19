# SLH-DSA-SHA2-128s (FIPS 205) — firma basada en funciones hash

**Código:** `qce/pqc/slhdsa.py` · **Pruebas:** `tests/test_slhdsa.py` · **Estado: puente `ctypes` NO REVISADO por terceros; el algoritmo es el de OpenSSL ≥ 3.5.**

La biblioteca `cryptography` instalada no trae SLH-DSA y reimplementarlo está prohibido por el proyecto, así que se usa el `libcrypto` de OpenSSL por `ctypes` (`EVP_PKEY`, `EVP_DigestSign`/`Verify`).
Es una alternativa cuya seguridad descansa solo en funciones hash (sin supuestos de retículos ni curvas); es lenta y grande (firma de 7856 bytes, ≈ 0,2 s) y por eso **no** se integra en el apretón QCE1
(cambiaría el protocolo): se ofrece como primitiva para raíces de confianza y declaraciones de larga vida.

## Qué se comprueba
Tamaños; firma válida; manipulación de mensaje, firma (cuatro posiciones), clave y contexto; límites de longitud y de contexto (255 inclusivo); aleatorizada por defecto y determinista a petición;
**verificación cruzada con la herramienta `openssl` en los dos sentidos** (nuestra firma la verifica `openssl pkeyutl -verify` con una clave pública en SubjectPublicKeyInfo estándar, y la firma de `openssl pkeyutl -sign` la verifica nuestro código);
falla cerrado sin OpenSSL ≥ 3.5 o si la biblioteca devuelve longitudes erróneas.

## Vectores oficiales NIST ACVP (ejecutados 2026-10-19)
`tests/vectors/acvp_slhdsa_subset.json` (procedencia, commit upstream y SHA-256 de los archivos originales dentro del propio JSON): **keyGen 10/10** (con las semillas oficiales `skSeed‖skPrf‖pkSeed` por `SlhDsaPrivateKey.from_seed`;
la clave privada y la pública coinciden byte a byte) y **sigVer 14/14** (externa, pura, con contexto: 2 firmas válidas y 12 inválidas, todas con el veredicto oficial).

## Qué NO se comprueba
- **No se ejecutaron** los vectores de `sigGen` (exigen inyectar el aleatorio de la firma, que la API no expone), ni los de `preHash`, ni los de la interfaz interna, ni los otros 11 conjuntos de parámetros: solo `SLH-DSA-SHA2-128s`.
- Los vectores verifican a OpenSSL (y la codificación del puente), no al puente en sí frente a fallos de memoria ni canales laterales.
- La clave privada (64 bytes) vive en la memoria del proceso. `from_seed` es solo para pruebas y réplica: con una semilla no aleatoria la clave no es segura.
