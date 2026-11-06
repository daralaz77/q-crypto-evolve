# Prueba diferencial de ML-KEM y ML-DSA (2026-11-06)

**Qué es:** una comprobación de conformidad entre implementaciones. Las mismas semillas se pasan a varias bibliotecas y se exige que den los mismos resultados. Herramientas en `tools/differential/`. Esto **no** prueba la seguridad de la composición QCE1 ni detecta canales laterales.

## Resultados (corrida del 2026-11-06, equipo del mantenedor)
| Prueba | Implementaciones | Casos por algoritmo | Comprobaciones | Discrepancias |
|---|---|---|---|---|
| `diff_pqc.py` | OpenSSL 3.6.4 (CLI), OpenSSL 4.0.3 (CLI), `cryptography` 50.0.2 | 300 | 23.100 | 0 |
| `diff_pure.py` | `kyber-py` 1.2.0 y `dilithium-py` 1.5.1 (Python puro) frente a OpenSSL 3.6.4 y 4.0.3 | 200 | 9.400 | 0 |

Algoritmos: ML-KEM-768 y 1024; ML-DSA-44, 65 y 87.

**Qué se comprueba:** (ML-KEM) misma clave pública desde la misma semilla; encapsular con una implementación y desencapsular con otra, en ambos sentidos; con texto cifrado alterado, el secreto de rechazo implícito es idéntico y distinto del real. (ML-DSA) firma determinista idéntica byte a byte (entre OpenSSL 3.6.4, OpenSSL 4.0.3 y Python puro; con `cryptography` solo se comprueba que su firma verifica); verificación cruzada que acepta lo válido y rechaza mensaje o firma alterados.

**Control negativo:** con la semilla corrompida a propósito en un lado, el arnés detecta discrepancias (`diff_pure.py 1 control`; solo ese script lo incluye). No es una prueba vacía.

## Límites
- `cryptography` embebe OpenSSL 4.0.3: comparte código con el CLI 4.0.3. La independencia real la aporta solo la implementación en Python puro.
- Esas bibliotecas de Python puro no son de tiempo constante ni están auditadas: son referencia, no código de producción.
- No cubre: mensaje vacío en ML-DSA (el CLI de OpenSSL lo rechaza), contexto de firma, prehash, ni encapsulación con aleatoriedad fija.
- NSS 3.125 y GnuTLS 3.8.13 se intentaron y se descartaron en este equipo: NSS no declara en sus headers la API de ML-KEM, y la compilación de GnuTLS no trae backend ML-DSA. Su interoperabilidad a nivel de handshake TLS se prueba aparte.
- Una corrida sin discrepancias no demuestra ausencia de errores; reduce el riesgo de divergencias entre implementaciones.
