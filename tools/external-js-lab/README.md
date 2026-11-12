# Laboratorio externo de verificación (JS / Node) — herramienta, no forma parte de `qce/`

> **Estado / Status:** laboratorio, sin revisión humana externa. *Research lab; no external human review.* **No usar en producción / Do not use in production.**

Verificación **independiente de la pila Python**: otra implementación (Node 26 / OpenSSL 3.6), oráculos de referencia propios, vectores oficiales y un modelo formal. Sirve para contrastar resultados con `tools/differential/` y `conformance/`; **no** está conectado a QCE1/QIL1 ni entra en el `release_id` (vive fuera de `qce/` y `tests/`).

## Créditos / Credits
- **Dirección del proyecto, ingeniería de prompts y coautoría:** Darwing John Pérez Aranguren (mantenedor). Definió los objetivos, las preguntas de verificación, los criterios de aceptación y las decisiones de alcance con las que se produjo este trabajo.
- **Código, pruebas, oráculos y modelo formal:** escritos por una instancia de Claude (Anthropic) bajo esa dirección y bajo las puertas de verificación del repositorio. Las firmas humanas (G5/G6) siguen **pendientes**.
- *Direction, prompt engineering and co-authorship: Darwing John Pérez Aranguren (maintainer). Code, tests, oracles and the formal model: written by an instance of Claude (Anthropic) under that direction.*

## Qué hay
| Ruta | Qué es |
|---|---|
| `src/aead.mjs` | AES-256-GCM / ChaCha20-Poly1305 con nonce aleatorio, lista de algoritmos cerrada |
| `src/xwing.mjs` | X-Wing KEM (draft-connolly-cfrg-xwing-kem): X25519 + ML-KEM-768, SHA3-256 |
| `test/support/` | **Oráculos de prueba** (ML-KEM FIPS 203, AES-GCM con IV arbitrario, X25519) en JS puro y **no constantes en tiempo**: solo para tests |
| `test/*.test.mjs` | Vectores Wycheproof/NIST ACVP/RFC/X-Wing, diferencial Node↔oráculo↔`@noble/post-quantum`, fuzzing, propiedades |
| `tools/tamarin/hybrid.spthy` | Modelo simbólico de composición híbrida (secreto ante compromiso de un componente) con variantes de control |
| `tools/semgrep-crypto.yml`, `tools/js/` | Reglas criptográficas propias de Semgrep y ESLint de seguridad (versiones fijadas) |
| `sidechannel/` | Análisis de tiempos estilo dudect (informativo) |
| `incidents/` | Incidentes y lecciones (INC-0001…0003) |

## Uso
```bash
cd tools/external-js-lab
./fetch-vectors.sh                       # descarga los vectores y verifica SHA-256 (no se redistribuyen en este repo)
npm ci --prefix tools/js                 # ESLint, eslint-plugin-security, @noble/post-quantum (aislados; no son dependencias del proyecto)
./run-lab.sh                             # suite + análisis estático + Tamarin + fallos inyectados + reversión
node sidechannel/timing.mjs              # análisis de tiempos (con control positivo)
```
Semgrep y Tamarin son opcionales: si no están instalados, `run-lab.sh` lo dice y los omite (no finge). Requiere Node ≥ 26 (ML-KEM nativo en `node:crypto`).
**Cuidado con npm:** ejecuta siempre `npm` dentro de `tools/js/` (ya tiene su `package.json`); sin él, npm sube de carpeta y modifica el proyecto padre (INC-0003).

## Resultados (última ejecución, 2026-11-11)
- 63/63 pruebas; 7/7 fallos inyectados detectados (nonce fijo, sin verificar tag, sin AAD, lista de algoritmos abierta, X-Wing sin label / sin pkX / sin ctX).
- Vectores: Wycheproof AES-GCM, ChaCha20-Poly1305, X25519 y ML-KEM-512/768/1024 (4 suites cada una); NIST ACVP ML-KEM-512/768/1024 (keyGen, encapsulación con `m` fijo vía oráculo, decapsulación, comprobación de claves); RFC 7748 y 5869; 3 vectores X-Wing. Todo correcto.
- ML-KEM contrastado a 3 bandas (OpenSSL vía Node, oráculo propio, `@noble/post-quantum`), 120 claves aleatorias, incluido el rechazo implícito.
- ESLint (security) sin avisos en `src/`; Semgrep sin hallazgos y con control positivo (ejecutado fuera de este repo, versión 1.95.0).
- Tamarin 1.12.0: el secreto de la clave solo se pierde si se comprometen **ambos** componentes; las variantes solo-clásico y solo-PQ se refutan (controles).
- Hallazgo real corregido: lista de algoritmos abierta (INC-0002).

## Límites (léelos antes de confiar)
- Los oráculos son de autoría de Claude y no constantes en tiempo; su fiabilidad proviene de reproducir vectores oficiales, no de revisión externa.
- Tamarin modela la **composición genérica** de forma abstracta: no verifica el código, no cubre autenticación del emisor, IND-CCA concreto ni el combinador exacto de X-Wing.
- X-Wing es un borrador (draft) y el archivo oficial solo trae 3 vectores.
- El análisis de tiempos es de caja negra y ruidoso (ruido de JIT/GC de Node): no demuestra ausencia de fugas. Sin Valgrind/ctgrind ni hardware dedicado.
- Sin auditoría humana independiente.
