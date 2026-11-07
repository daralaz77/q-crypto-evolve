# QCE1 y QIL1 — resumen de una página para quien revise

**Qué pedimos:** una revisión crítica (lo más útil es encontrar lo que está mal) de **dos composiciones criptográficas propias**: el apretón de manos híbrido poscuántico **QCE1** (X25519 + ML-KEM-768, firma Ed25519 + ML-DSA-65, HKDF-SHA256) y la capa interna **QIL1** (clave QKD sobre TLS 1.3). No pedimos revisar las primitivas (ML-KEM, ML-DSA, HKDF, AEAD): se asumen seguras. Alcance completo: `LEEME.md`. Plantilla de informe: `PLANTILLA_INFORME.md`.

**Transparencia:** es un laboratorio. **Toda la autoría (código, especificación, modelo formal, pruebas) es de instancias de Claude**; la única revisión que hubo fue de otras instancias de Claude. **Ninguna persona experta la ha revisado**: esa es la que se pide.

## Si solo tiene una hora
Lea `docs/QCE1_SPEC.md` (§7, §11, §13) y responda las preguntas 1 a 4 de `PREGUNTAS_ABIERTAS.md` (combinación de claves y derivación HKDF). Si es de QKD o TLS: preguntas 21 a 24 (QIL1).

## Qué hay de comprobado (estado a 2026-11-06, release `7a26ae171848244a`)
| Evidencia | Qué dice | Qué NO dice |
|---|---|---|
| Puertas G1–G4 y G6 pasan; G5 (revisión independiente) está pendiente | Integridad, 907 pruebas, seguridad y regresión OK; hay autorización humana del mantenedor | G5 sigue sin cumplirse: por eso se pide esta revisión |
| Prueba de mutación: 447 de 447 mutantes detectados (5 declarados equivalentes) | Las pruebas detectan roturas de los controles listados | No descubre vulnerabilidades desconocidas |
| Vectores NIST ACVP (ML-KEM, ML-DSA, SLH-DSA) y `docs/PRUEBA_DIFERENCIAL_PQC.md` (0 discrepancias frente a OpenSSL 3.6/4.0 y a una implementación independiente en Python puro) | Las primitivas se comportan como el estándar | No prueba la seguridad de la composición |
| Modelo Tamarin simbólico de QCE1 y QIL1 | Propiedades del diseño en el modelo | Sin modelo computacional, sin capa de registros, sin revisión humana |
| `docs/QIL1_CONTRASTE_LITERATURA.md` | Ni el teorema de un solo uso de Dey–Safavi-Naini ni la combinación de Giestinhas–Spiller cubren QIL1; sus registros dependen del supuesto computacional del AEAD | No es una validación; los artículos se leyeron de forma parcial |

## Preguntas que más nos ayudarían (resumen)
1. ¿La mezcla de la clave QKD por concatenación dentro de HKDF, y `th` a la vez como sal y como contexto, da separación de dominios suficiente? (preguntas 1–3 y 22)
2. ¿`tls-unique` (no estándar en TLS 1.3) basta como ligadura de QIL1, o hay un ataque de triple apretón de manos? (pregunta 21)
3. ¿Faltan lemas de *unknown-key-share*, KCI o revelación de claves de sesión? (preguntas 12 y 25)
4. ¿Conviene sustituir nuestro combinador de KEM por uno público como X-Wing (borrador IETF)? (pregunta 20)

## Cómo verificar lo que recibe
`python -m qce review-package --verify <zip>` comprueba que todos los archivos coinciden con `MANIFEST.sha256`. El manifiesto **no está firmado**: compare el SHA-256 del zip con el que le comunicó el remitente por **otro canal**. Reproducción completa: `REPRODUCCION.md`.

## Contacto para hallazgos graves
**[A completar por quien envía el paquete]** — avise antes de publicar; política de divulgación en `SECURITY.md` (90 días, coordinada).

Material posterior al paquete, disponible en el repositorio público (`github.com/daralaz77/q-crypto-evolve`): `docs/PRUEBA_DIFERENCIAL_PQC.md`, `docs/QIL1_CONTRASTE_LITERATURA.md` y `tools/differential/`.
