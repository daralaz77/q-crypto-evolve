# SLH-DSA-SHA2-128s (FIPS 205) — firma basada en funciones hash

**Código:** `qce/pqc/slhdsa.py` · **Pruebas:** `tests/test_slhdsa.py` · **Estado: puente `ctypes` NO REVISADO por terceros; el algoritmo es el de OpenSSL ≥ 3.5.**

La biblioteca `cryptography` instalada no trae SLH-DSA y reimplementarlo está prohibido por el proyecto, así que se usa el `libcrypto` de OpenSSL por `ctypes` (`EVP_PKEY`, `EVP_DigestSign`/`Verify`).
Es una alternativa cuya seguridad descansa solo en funciones hash (sin supuestos de retículos ni curvas); es lenta y grande (firma de 7856 bytes, ≈ 0,2 s) y por eso **no** se integra en el apretón QCE1
(cambiaría el protocolo): se ofrece como primitiva para raíces de confianza y declaraciones de larga vida.

## Qué se comprueba
Tamaños; firma válida; manipulación de mensaje, firma (cuatro posiciones), clave y contexto; límites de longitud y de contexto (255 inclusivo); aleatorizada por defecto y determinista a petición;
**verificación cruzada con la herramienta `openssl` en los dos sentidos** (nuestra firma la verifica `openssl pkeyutl -verify` con una clave pública en SubjectPublicKeyInfo estándar, y la firma de `openssl pkeyutl -sign` la verifica nuestro código);
falla cerrado sin OpenSSL ≥ 3.5 o si la biblioteca devuelve longitudes erróneas.

## Qué NO se comprueba
- **Los vectores oficiales NIST ACVP de SLH-DSA no se han ejecutado** (no se descargaron: habría que traerlos de un repositorio público). La verificación cruzada usa la misma biblioteca por otra interfaz: demuestra que el puente y la codificación
  estándar son coherentes, no que OpenSSL cumpla FIPS 205. **Pendiente:** correr los vectores ACVP como se hizo con ML-KEM y ML-DSA.
- Seguridad de memoria del puente, canales laterales, y que la clave privada (64 bytes) vive en la memoria del proceso.
