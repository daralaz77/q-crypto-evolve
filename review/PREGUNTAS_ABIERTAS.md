# Preguntas abiertas para el revisor

Cada pregunta indica **dónde mirar**, **por qué importa** y **qué cambiaría si la respuesta es “no”**. Las 1–10 vienen de la especificación (§13); las 11–20 salieron del modelo formal, de la conformidad y de las auditorías internas.

## A. Del diseño (especificación §13)

| # | Pregunta | Dónde | Por qué importa | Si la respuesta es «no» |
|---|---|---|---|---|
| 1 | La clave QKD se mezcla por concatenación (`secret = ss ‖ qkd_key`) dentro de HKDF y no entra en el transcript (solo su id). ¿Basta, o hace falta un combinador con separación de dominios por componente? | Spec §10, §6 | El modelo formal la trata como un término más; no prueba el combinador | Rediseñar la mezcla (p. ej. HKDF-Extract por componente) |
| 2 | `salt = th` y `th` también va en `info`. ¿Redundante inofensivo o riesgo de interacción? ¿Conviene una etiqueta distinta por dirección? | Spec §7 | Es la derivación central | Cambiar el esquema de derivación (cambio de nivel 3) |
| 3 | Una sola salida HKDF de 104 bytes dividida en 5 trozos (claves, confirmación, prefijos de nonce). ¿Extract y Expand por separado con etiquetas explícitas? | Spec §7 | Separación de claves por propósito | Expand con `info` distinto por clave |
| 4 | La firma del servidor no cubre `ct` (el texto cifrado del cliente); la confirmación MAC sí cubre todo el transcript. El modelo muestra que si caen **los dos** KEM, cae la autenticación de la sesión aunque la firma siga válida. ¿Es aceptable? ¿Hay un ataque de unknown-key-share o de re-encapsulación no capturado? | Spec §6, `docs/QCE1_FORMAL.md` §3.3 y §3.5 | Es la decisión de diseño más discutible | Añadir una segunda firma sobre `ct` o un mensaje extra |
| 5 | No hay autenticación del cliente (no objetivo). ¿Está bien delimitado para el caso de uso previsto? | Spec §1 | Un uso mutuo requeriría rediseñar | Añadir autenticación de cliente |
| 6 | `session_id` = 16 bytes del transcript, y la dirección va en el AAD además de usar claves distintas por sentido. ¿Redundancia útil o confusión? | Spec §8 | Anti-reflexión | Simplificar |
| 7 | Nonce de registro = prefijo de 4 bytes derivado + contador de 64 bits. ¿Alguna interacción con AES-GCM al renegociar? | Spec §8 | Reutilización de nonce = fallo catastrófico | Derivar el prefijo de otra forma |
| 8 | `suites` se codifica como texto separado por comas (máx. 8). ¿Ambigüedad o inyección más allá de las validaciones actuales? | Spec §5, `session.py` | Negociación = superficie de degradación | Codificación binaria con longitudes |
| 9 | La ventana anti-repetición vive solo en memoria. La renegociación obligatoria tras reiniciar, ¿es suficiente? | Spec §8 | Repetición entre reinicios | Persistir estado o forzar claves nuevas |
| 10 | Un solo intento de `ClientFinish`: tras un fallo el apretón se cierra. ¿Facilita denegación de servicio a un atacante en la ruta? | Spec §6 | Disponibilidad | Permitir reintentos (el modelo ya los permite) |

## B. Del modelo y la conformidad

| # | Pregunta | Dónde | Por qué importa | Si la respuesta es «no» |
|---|---|---|---|---|
| 11 | Cada KEM se modela como cifrado de un valor fresco con clave pública (`encx/decx`, `encm/decm`) y la «rotura» como `dlog(pk)=sk` para todas las claves. ¿Es una abstracción adecuada para el combinador X25519 + ML-KEM, o oculta algo (p. ej. propiedades de ML-KEM con rechazo implícito)? | `formal/qce1.spthy`, `docs/QCE1_FORMAL.md` §1 | De ello dependen todos los veredictos | Modelar el KEM con una teoría más fina |
| 12 | No hay lemas de **unknown-key-share**, **KCI**, **revelación de clave de sesión** ni de **compromiso del estado efímero**. ¿Cuáles faltan y son necesarios para el caso de uso? | `docs/QCE1_FORMAL.md` §3.5 y §5 | Cobertura de propiedades | Ampliar el modelo |
| 13 | La rotura de un componente es total y permanente. ¿Interesa modelar roturas parciales o escalonadas (rotura **después** de la sesión para el secreto hacia adelante poscuántico)? | `docs/QCE1_FORMAL.md` §1 | Secreto hacia adelante frente a un ordenador cuántico futuro | Añadir variantes con orden temporal |
| 14 | El modelo permite reintentos de `ClientFinish`; el código no. ¿La diferencia (código más estricto) es inofensiva? | `docs/QCE1_CONFORMANCE.md` §4 | Conformidad en un solo sentido | Alinear modelo y código |
| 15 | Las funciones `h`, `comb`, `kc2s`… son oráculos aleatorios inyectivos y la codificación con longitudes se supone inyectiva. ¿Es razonable para `H(x1…xn)` con prefijos de 4 bytes y campos ≤ 16 KiB? | Spec §3, modelo | Ataques de ambigüedad de codificación | Fijar un formato canónico más estricto |
| 16 | La conformidad se hace por **verificación en ejecución** de los lemas sobre trazas y comparación de guardas con un oráculo independiente (escrito por la misma instancia que el código). ¿Es convincente o hace falta generar trazas desde el propio Tamarin? | `docs/QCE1_CONFORMANCE.md` §5 | Confianza en que el modelo describe el código | Importar trazas del modelo y reproducirlas |

## C. Del código

| # | Pregunta | Dónde | Por qué importa |
|---|---|---|---|
| 17 | Los MAC y hashes se comparan con `hmac.compare_digest`; el resto es Python (no constante en tiempo). ¿Hay comparaciones o ramas dependientes de secretos que se nos escapan? | `qce/protocols/session.py`, `qce/symmetric/aead.py` | Canales laterales locales |
| 18 | `HKDF(salt=None)` en el combinador del KEM: ¿equivale a sal de ceros y es correcto para entrada de alta entropía? | `qce/pqc/hybrid.py` `_combine` | Composición del KEM |
| 19 | Firma híbrida: Ed25519 firma `ctx ‖ 0x00 ‖ mensaje` y ML-DSA usa el parámetro de contexto nativo. ¿Separación de dominios suficiente y sin confusión entre esquemas? | `qce/pqc/hybrid.py` | Ataques entre protocolos |
| 20 | El combinador `HKDF(ss_m ‖ ss_x, etiqueta ‖ ct ‖ pk)` vincula el texto cifrado completo y la clave pública del receptor. ¿Existe un resultado conocido (p. ej. de la literatura sobre combinadores de KEM) que lo respalde o lo contradiga? Compárelo con la construcción de X-Wing. | `qce/pqc/hybrid.py`, Spec §4.1 | IND-CCA del híbrido |

## E. De QIL1 (capa interna con clave QKD sobre TLS 1.3; spec `docs/QKD_LAYER_SPEC.md` §10)

| # | Pregunta | Dónde | Por qué importa | Si la respuesta es «no» |
|---|---|---|---|---|
| 21 | `tls-unique` (48 bytes en OpenSSL/TLS 1.3, no estándar; RFC 9266 no disponible en Python) como única ligadura: ¿hay un ataque de «triple apretón» u otro que lo invalide en TLS 1.3? | spec §3, §10.1 | De la ligadura depende que un certificado falso no sirva | Usar el exportador RFC 9266 o rediseñar |
| 22 | `th` es sal y contexto a la vez y un mismo `K` produce tres claves con `info` distinto: ¿separación de dominios suficiente? | spec §4 | Separación de claves | Derivación con Extract/Expand separados |
| 23 | El servidor reserva `K`, la consume al verificar al cliente y la libera si falla, con `HANDSHAKE_TIMEOUT`: ¿es aceptable la retención de hasta ese plazo? | spec §6 | Disponibilidad | Límite de tasa por origen |
| 24 | El servidor recibe su huella de certificado como parámetro: ¿hay un camino en que use una huella distinta del certificado presentado? | spec §10.4 | Ligadura al certificado | Obtener la huella del propio socket |
| 25 | El modelo acota los abortos a uno por clave para que Tamarin termine y solo tiene un servidor: ¿la cota invalida las conclusiones? ¿Hace falta UKS con varios servidores? | `docs/QKD_LAYER_FORMAL.md` §3, §5 | Cobertura del modelo | Ampliar el modelo con inducción o varios servidores |
| 26 | `later_qkd_leak_exposes_past_session` muestra que la confidencialidad pasada ante una filtración de `K` descansa en que el valor de ligadura de TLS siga secreto: ¿es una garantía útil o engañosa? | `docs/QKD_LAYER_FORMAL.md` §3 | Lo que se puede prometer | Retirar la afirmación |

| 27 | El parámetro `group="X25519"` del puente PSK existe solo para interoperar con pilas sin híbrido. ¿Es aceptable tener esa vía en el código, aun con lista cerrada y atestación, o debería vivir solo en las pruebas? | `qce/transport/tls13_psk.py` | Superficie de degradación | Quitar el parámetro y probar la interoperabilidad con una pila que traiga el híbrido |

## D. Alcance que usted puede recortar o ampliar

Si alguna de estas preguntas está fuera de su especialidad, déjela en blanco: es más útil una respuesta firme a tres preguntas que una opinión tibia a veinte.
