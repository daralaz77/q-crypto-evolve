# QIL1 frente a la literatura de QKD + PQC (2026-11-06)

**Qué es:** una comparación de la capa QIL1 (`docs/QKD_LAYER_SPEC.md`) con dos artículos recientes. **Qué no es:** una validación de QIL1. Ninguno de los dos artículos analiza QIL1 ni protocolos como ella, y yo (una instancia de Claude) los leí de forma parcial (ver «Cómo se leyó»). Nada aquí sustituye la revisión humana experta (G5).

## Los dos artículos
1. **Dey y Safavi-Naini**, *Secure Composition of Quantum Key Distribution and Symmetric Key Encryption* (arXiv:2501.08435, ISIT 2025). Define un **qKEM** (una clave QKD vista como encapsulado de clave) y un cifrado híbrido **qHE = qKEM + DEM**. Teorema 4: si el qKEM es ε-seguro y el DEM es σ-seguro con seguridad de **un solo uso** (IND-OT), el qHE es (ε+σ)-seguro IND-OT. El canal clásico se supone **autenticado**. Declaran como trabajo futuro el uso de la clave establecida para cifrado híbrido de **varios** mensajes.
2. **Giestinhas y Spiller**, *Information-Theoretic Solutions for Seedless QRNG Bootstrapping and Hybrid PQC-QKD Key Combination* (arXiv:2603.26907, v3). Propone **combinar** una clave PQC y una QKD con un extractor con semilla (familia de Toeplitz, lema de «leftover hash» cuántico) en lugar de XOR o de un KDF. Supone claves **independientes** y modela la clave PQC con entropía HILL. Su conclusión es que, si el adversario controla la generación de una de las claves, no se garantiza una extracción segura; si se revela una clave, la salida queda limitada por la otra. Sobre un intercambio de claves autenticado (variante tipo Muckle#), el propio artículo dice que **no da una prueba de seguridad** y la deja para trabajo futuro.

## Qué se aplica a QIL1 y qué no

| Punto | Literatura | QIL1 | Consecuencia |
|---|---|---|---|
| ¿Combina clave PQC y clave QKD? | El artículo 2 trata de eso | **No**: es una cascada (TLS híbrido por fuera, capa QKD por dentro, `LIMITATIONS.md`) | Los teoremas de combinación del artículo 2 **no se aplican** a QIL1. La cascada evita el problema del combinador, a costa de no mezclar claves. |
| Primitiva que usa la clave QKD | Artículo 2: extractor con semilla (seguridad teórica de la información si se cumplen sus supuestos); KDF = solo seguridad computacional | HKDF-SHA-256 con sal `th` | La seguridad de las claves derivadas de QIL1 es **computacional**; QIL1 no reclama más (§1 y §7 de su especificación). No hay contradicción, pero tampoco respaldo del artículo 2 para HKDF. |
| Uso de la clave establecida | Artículo 1: el teorema cubre **un solo uso** del DEM; varios mensajes es trabajo futuro | AEAD ChaCha20-Poly1305, nonce por contador, hasta `MAX_RECORDS` registros por dirección | **El teorema del artículo 1 no cubre este uso.** La seguridad de los registros de QIL1 descansa en el supuesto computacional del AEAD y no en el teorema citado. |
| Autenticación del canal clásico | Ambos la suponen | QIL1 la obtiene de TLS 1.3 y de las etiquetas `ts`/`tc` | Coherente; la fuerza depende del TLS y de que la clave QKD sea realmente secreta. |
| Ligadura a la transcripción | Artículo 2: meter la transcripción en la entrada del extractor; avisa de que, en Toeplitz, la transcripción solo da separación de dominios | `th` (valor de ligadura TLS, huella del certificado, `kid`, nonces) como sal y contexto | Idea alineada. En QIL1 `th` entra como sal de HKDF, no en un extractor de Toeplitz, así que el aviso de maleabilidad no se transfiere. |
| Clave controlada por el adversario | Artículo 2: sin garantía | Fuente de clave QKD: **simulador** (`os.urandom`) | Mismo límite: si el dispositivo o el *broker* están comprometidos, no hay garantía. Ya figura en `LIMITATIONS.md`. |

## Resultado
- **No encontré contradicción** entre QIL1 y estos dos artículos, pero tampoco **respaldo formal**: no tratan su construcción.
- **Precisión que falta en la especificación de QIL1** (candidata a cambio de redacción, no de código): dejar dicho que la confidencialidad de los registros es computacional y que el teorema de un solo uso de la literatura no la cubre.
- **Pregunta para el revisor humano:** ¿basta HKDF con sal `th` para separar dominios y derivar tres claves de una clave QKD, o conviene una construcción con análisis publicado?
- **Opción de diseño no adoptada:** una mezcla real de clave PQC y QKD, mediante la PSK externa de TLS 1.3 (opción A de `docs/QKD_TLS_OPTIONS.md`), no se basa en estos dos artículos y hoy no es posible desde Python.

## Cómo se leyó (límites de esta comparación)
- Artículo 1: texto completo extraído del PDF; leí el planteamiento, el Teorema 4 y las conclusiones, no todas las demostraciones.
- Artículo 2: HTML de la v3; leí las secciones 1 a 6, parte de la 7 y el Apéndice A, pero no los últimos ~2.000 caracteres. Las cifras de tamaños de clave y costes las tomo de ese texto sin recomprobarlas.
- No consulté las demostraciones ni el resto de la literatura (por ejemplo los modelos Muckle/Muckle# originales).
