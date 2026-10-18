# Modelo formal de QCE1 (Tamarin Prover 1.12.0)

**Archivos:** `formal/qce1.spthy` (modelo), `formal/expected.json` (veredictos esperados por configuración), `qce/evolve/formal.py` (ejecutor y mutantes del modelo).
**Reproducir:** `python -m qce formal` (≈2 min) o `QCE_FORMAL=1 python -m pytest tests/test_formal_model.py`. Requiere `brew install tamarin-prover/tap/tamarin-prover`.
**Alcance:** prueba el **diseño** de QCE1 bajo primitivas ideales (modelo simbólico). No prueba el código, ni las primitivas, ni canales laterales.

## 1. Cómo se modela la rotura de un componente

| Componente | Modelo | «Roto» (`-D…`) |
|---|---|---|
| X25519 | KEM abstracto: `encx/decx` con claves `pkx(sk)` | `BREAKX`: el atacante calcula `sk` desde `pkx(sk)` (para TODAS las claves) |
| ML-KEM-768 | KEM abstracto independiente: `encm/decm` | `BREAKM` |
| Ed25519 | firma abstracta `sige/vere` | `BREAKE` |
| ML-DSA-65 | firma abstracta independiente `sigd/verd` | `BREAKD` |
| QKD | clave secreta mezclada en `secret = ⟨K, qk⟩`, nunca entregada al atacante | `QKD` |

La rotura es la **más fuerte posible** (el atacante resuelve el problema difícil siempre), no un fallo parcial. La firma híbrida exige **ambas** verificaciones (`Eq(...) = true` dos veces).

## 2. Resultados (todos ejecutados; 11 configuraciones × 7 lemas)

`V` = verificado · `F` = falsificado (existe un ataque o una traza). Las `F` marcadas con ★ son las **esperadas**: demuestran que el lema no es vacío.

| Configuración | secreto c→s | secreto s→c | acuerdo inyectivo | sin degradación | firma liga Hello | ejecutable | cliente no autenticado |
|---|---|---|---|---|---|---|---|
| sin roturas | V | V | V | V | V | V | V |
| X25519 roto | V | V | V | V | V | V | V |
| ML-KEM roto | V | V | V | V | V | V | V |
| Ed25519 roto | V | V | V | V | V | V | V |
| ML-DSA roto | V | V | V | V | V | V | V |
| X25519 + Ed25519 rotos | V | V | V | V | V | V | V |
| ML-KEM + ML-DSA rotos | V | V | V | V | V | V | V |
| **X25519 + ML-KEM rotos** | F★ | F★ | F★ | F★ | **V** | V | V |
| **Ed25519 + ML-DSA rotos** | F★ | F★ | F★ | F★ | F★ | V | V |
| QKD | V | V | V | V | V | V | **F** |
| QKD + X25519 + ML-KEM rotos | **V** | **V** | **V** | **V** | V | V | **F** |

`V` en «cliente no autenticado» significa: existe una traza en la que el servidor completa sin cliente honesto (es un **no objetivo** confirmado).

## 3. Qué se concluye (y qué no)

1. **La propiedad híbrida se cumple tal como se pretendía:** basta con que sobreviva **un** KEM y **una** firma (cualquier combinación) para mantener secreto, secreto hacia adelante, acuerdo inyectivo con el servidor fijado y anti-degradación.
2. **Cada mecanismo tiene su papel, y la especificación lo decía mal.** El anti-degradación se sostiene por dos vías independientes: la **firma** sobre el ClientHello (aguanta incluso con los dos KEM rotos: lema `signature_binds_hello`) y el **MAC de confirmación** sobre todo el transcript (solo mientras algún KEM resista). La prueba del modelo lo muestra: quitar `m1` de lo firmado **no** rompe `no_downgrade` con los KEM sanos (lo cubre el MAC), pero sí rompe `signature_binds_hello` con ambos KEM rotos.
3. **Si caen los dos KEM, cae la autenticación de la sesión aunque la firma siga siendo válida:** el servidor sigue emitiendo un Hello auténtico, pero el texto cifrado del cliente (`ct`) no está firmado y la confirmación del servidor depende del secreto KEM. Es lo esperable en este diseño; conviene que el revisor lo confirme como aceptable (pregunta abierta 4).
4. **Hallazgo no previsto en la especificación (QKD):** al mezclar una clave QKD secreta, el servidor **solo** puede completar el apretón con quien la conozca, así que la clave QKD actúa como **autenticación implícita del cliente** (el lema «cliente no autenticado» pasa a falso) y mantiene secreto y acuerdo incluso con ambos KEM rotos. Depende de que `qk` sea de verdad secreta y de un solo uso (el broker lo impone, el modelo lo asume).
5. **No se ha formalizado un lema de unknown-key-share.** El acuerdo inyectivo incluye la identidad `S` y la huella va dentro de lo firmado, y no apareció ningún ataque, pero eso no equivale a haberlo probado en un modelo con varios clientes y servidores de confianza mutua.

## 4. El modelo tiene dientes (mutantes del modelo)

| Defecto introducido en el modelo | Lema que debe caer | Resultado |
|---|---|---|
| La firma no cubre el ClientHello (con ambos KEM rotos) | `signature_binds_hello` | cae ✔ |
| La firma no cubre la clave KEM efímera | `secrecy_c2s`, `secrecy_s2c` | caen ✔ |
| El cliente no comprueba el MAC del servidor | `injective_agreement` | cae ✔ |

## 5. Lo que este modelo NO cubre

- **Capa de registros** (AEAD, ventana, no reflexión): propiedad 6 de la especificación, sin modelar.
- **Revelación de claves de sesión o de estado efímero** (no hay lemas de KCI, compromiso de sesión ni de aleatoriedad defectuosa).
- **Longitudes, codificación y política de suites** más allá de una función abstracta `pick`; el cliente no comprueba «suite ∈ ofrecidas» en el modelo.
- **Rotura parcial o gradual** de una primitiva, y combinadores computacionales exactos (haría falta CryptoVerif/EasyCrypt).
- **Conformidad modelo-código:** hoy solo se comprueba que las fórmulas de la especificación coinciden con el código (`tests/test_spec_anchors.py`). Falta el paso 6: generar trazas del código real y compararlas con el modelo.
- **Revisión por una persona experta** del modelo y de la especificación (paso 7): sin ella, el modelo puede estar modelando algo distinto de lo que se quiso.
