# Qué encuentra una herramienta independiente en código escrito por una IA bajo puertas de verificación

**Caso de estudio de Q-Crypto Evolve** · versión 1 · 22 de octubre de 2026 · Darwing John Pérez Aranguren · director@daralaz.com

> **Transparencia:** el código, las pruebas, los modelos formales y este informe los redactó una instancia de Claude (Anthropic) bajo la dirección del titular del proyecto. El titular lo leyó y lo aprobó para su publicación. **Ninguna persona ajena al proyecto ha revisado el código.** Las cifras de este informe salen de los archivos del repositorio y se pueden reproducir (ver §8).

**Summary (EN).** An AI (Claude) wrote a post-quantum hybrid-crypto lab with a QKD key-delivery client and a TLS 1.3 PSK bridge, under mechanical verification gates (612 tests, mutation testing with 389 mutants, a hash-chained incident ledger, a reproducible review package). We then cross-checked its ETSI GS QKD 014 emulator with an independent third-party tool, `qkdsec`. In one session the tool exposed **two real defects that all our gates had missed**, because our tests shared the author's assumptions. Both are fixed with regression tests and mutants. We state what this does *not* show: no human review yet, one independent tool only, QKD tested against emulators only.

---

## 1. La pregunta
¿Qué valor tiene el código que escribe una IA cuando lo rodea un método de verificación estricto, y dónde falla ese método? No buscamos demostrar que el código sea correcto: buscamos medir **qué atrapa el método por sí solo y qué solo atrapa un tercero**.

## 2. Qué se construyó
Un laboratorio abierto (Apache-2.0, <https://github.com/daralaz77/q-crypto-evolve>) de criptografía poscuántica híbrida: intercambio de claves X25519+ML-KEM, firma Ed25519+ML-DSA, un cliente de la interfaz ETSI GS QKD 014 con un emulador de KME, un puente TLS 1.3 con PSK externa derivada de la clave QKD y el grupo híbrido `X25519MLKEM768`, e integración de HSM por PKCS#11. Es un **laboratorio**: no se recomienda su uso en producción (`LIMITATIONS.md`).

## 3. El método (las «puertas»)
Seis puertas mecánicas que un agente no puede relajar para que una prueba pase:

| Puerta | Qué exige | Estado en el release `b3dfc708179da391` |
|---|---|---|
| G1 Integridad | cadenas de registro con hash íntegras, dependencias fijadas con hash, SBOM, umbrales que no se debilitan | pasa |
| G2 Funcionalidad | batería de pruebas, con vectores oficiales NIST ACVP y fuzzing | **612 pruebas**, pasan |
| G3 Seguridad | sin secretos ni malos usos, dependencias limpias y **mutación completa** | pasa (**389 mutantes**; exige puntuación 1,0, un mutante «canario» sin efecto que debe sobrevivir y un tope de equivalentes declarados) |
| G4 Regresión | cada incidente histórico se reproduce y sigue corregido | 33 de 33 incidentes reproducidos (INC-0029 cerrado en la v1.1, §6) |
| G5 Independencia | declaración firmada de **una persona revisora distinta del implementador** | **pendiente** |
| G6 Autorización | autorización humana firmada para el código exacto | firmada por el titular |

Cada fallo se registra en un libro de incidentes encadenado por hash con causa raíz, prueba de reproducción y estado de la lección. El `release_id` liga las firmas al código exacto: cambiar una línea las invalida. Hay un paquete de revisión reproducible desde cero.

**La IA no firma las puertas humanas.** Firma una declaración de autoría y nada más.

## 4. Lo que el método atrapó por sí solo
33 incidentes en los primeros días del repositorio (el historial empieza el 17 de octubre de 2026). Los encontraron las propias pruebas, la mutación, la atestación del transporte y **auditorías adversariales hechas por subagentes, es decir, por otras instancias de la misma IA** (no por personas ni por herramientas de terceros). Por causa: 18 de código, 9 de pruebas insuficientes, 3 de configuración y 2 de especificación (más INC-0029, cerrado como probable artefacto de la emulación, §6). Los más instructivos son los que **un test verde habría dejado pasar**:

- **INC-0002 — la mutación pasaba en vacío** (lo halló una auditoría adversarial de un subagente, con prueba de concepto). La puntuación 1,0 era falsa: el entorno aislado no copiaba un archivo, la colección de pruebas fallaba y cualquier código de salida ≠ 0 se contaba como «mutante detectado». Se arregló exigiendo una línea base verde, mutantes mínimos y el canario.
- **INC-0018 — un servidor que comparaba solo 16 de los 32 bytes del MAC pasaba toda la batería.** Las pruebas alteraban bytes al azar y la cola del mensaje casi nunca se tocaba. Lo destapó un mutante que sobrevivía, no una prueba.
- **INC-0016 — mi propio arreglo no detectaba nada.** Una comprobación de enlaces simbólicos se hacía sobre una ruta ya resuelta, y la prueba original pasaba por otro motivo. Lo destapó un superviviente de la mutación.
- **INC-0019 / INC-0020 — configuración ignorada en silencio.** Si se importaba `cryptography` (o `secrets`) antes de fijar `OPENSSL_CONF`, OpenSSL ignoraba la configuración que fija el grupo híbrido sin ningún error y el transporte quedaba abierto a grupos clásicos. Lo cazó la atestación del propio transporte, que falló cerrado en el primer intento.
- **INC-0008 / INC-0017 — un redactor de secretos que destruía evidencia.** Una regla de base64 demasiado ancha borraba nombres de prueba legibles y rompió la reproducción de otros incidentes.

El patrón: **el defecto no estaba en lo que probamos mal, sino en lo que la prueba no podía ver**. La mutación hizo visibles INC-0016 e INC-0018, y la atestación que falla cerrado hizo visibles INC-0019 e INC-0020.

## 5. Lo que solo un tercero encontró
El 22 de octubre contrastamos el emulador de KME con [`qkdsec`](https://github.com/John-Jepsen/qkdsec) 0.3.0 (Apache-2.0, de otra persona), que trae un cliente ETSI 014 y una sonda de conformidad (`qkdsec doctor`). Lo instalamos en un entorno aparte, verificando el SHA-256 de la rueda contra el publicado y leyendo antes su código.

Resultado de la sonda: **1 de 10 correctas al inicio, 8 de 10 tras corregir.** Dos defectos reales **nuestros**, que pasaban las 600 pruebas y la mutación:

1. **INC-0032 — certificados sin identificadores de clave.** La PKI de laboratorio no ponía *Authority/Subject Key Identifier* (RFC 5280). Un cliente TLS estricto (`requests`, el contexto por defecto de Python ≥ 3.13) los rechazaba. Nuestras pruebas usaban contextos no estrictos y `curl` aceptaba los certificados, por eso nadie lo vio.
2. **INC-0033 — emulador que se alejaba del estándar.** Implementaba solo `POST`, inventaba mensajes de error y respondía 400 donde ETSI GS QKD 014 pide 401 (la SAE que no recibió la clave no puede recogerla). Faltaban las formas `GET` (§5.3, §5.4, §6.2, §6.4).

Ambos se corrigieron con **pruebas de regresión que fallan con el código anterior** y 11 mutantes nuevos.

De los dos resultados que la sonda seguía marcando, **ninguno era defecto nuestro**, y lo comprobamos contra el texto del estándar: la sonda espera un 404 que la versión 1.1.1 no define (solo 400, 401 y 503) y usa el mismo certificado para pedir y recoger la clave, algo que el estándar no permite. Con la biblioteca cliente de `qkdsec` y dos certificados (maestra y esclava) la ida y vuelta es correcta por `GET` y por `POST`.

**Por qué importa:** nuestras pruebas y nuestro emulador los escribió el mismo agente con las mismas suposiciones. Verificarse a sí mismo comparte los puntos ciegos del autor. Una herramienta con otras suposiciones los encontró en una sesión.

## 6. Lo que este informe NO demuestra
- **No hay revisión humana externa.** G5 sigue pendiente. Nada aquí sustituye a una persona experta que lea el código.
- **Una sola herramienta independiente y una sola sonda.** Dos hallazgos no son una tasa. No sabemos cuántos defectos quedan.
- **QKD solo contra emuladores.** Sin KME real, el contraste con la realidad de un fabricante no existe.
- **Las «auditorías independientes» internas fueron de otras instancias de la misma IA**, con sus mismos sesgos: no cuentan como revisión independiente.
- **La mutación mide si las pruebas detectan fallos inyectados, no si el código es correcto.** Y las pruebas las escribió la misma IA.
- **Las pruebas de seguridad criptográfica reposan en ML-KEM/ML-DSA** (supuestos de dureza) y en OpenSSL, no en este código. El puente TLS por `ctypes` es nuestro y **no está revisado**.
- **Un incidente (INC-0029) seguía abierto al publicarse este informe y se cerró después:** GnuTLS 3.8.9 contra nuestro servidor PSK fallaba entre el 15 % y el 66 % de los apretones **solo** en x86_64 emulado. El 27 de octubre de 2026, la integración continua en x86_64 y arm64 **nativos** (Debian 13, GnuTLS 3.8.9) repitió la prueba 100 veces por arquitectura: 0 fallos en 500 pruebas. Se cerró atribuyéndolo, como **probable** y sin mecanismo demostrado, a la emulación. No descarta una tasa de fallo muy baja; la CI lo vigila en cada cambio. (El preprint de Zenodo v1.0 lo describe como abierto, que era el estado de ese día; la v1.1 lo corrige.)
- **No es FIPS 140-3.** Hay un análisis (`docs/FIPS_140_3.md`) y un alcance acotado, no una certificación.

## 7. Lecciones que creemos útiles a otros
1. **Un tercero con otras suposiciones vale más que más pruebas propias.** Mide contra una herramienta ajena cuanto antes.
2. **Mide que tus pruebas pasan por el motivo correcto.** La mutación destapó INC-0016 e INC-0018. Exige línea base verde y un mutante canario.
3. **Falla en voz alta.** INC-0019 e INC-0020 eran configuración ignorada en silencio y solo se vieron porque el transporte comprueba lo que negoció y falla cerrado.
4. **Ata las firmas al código exacto** y **no dejes que quien implementa firme la revisión**.
5. **Publica los incidentes.** El libro de errores es la evidencia más honesta de que el método funciona, y de dónde no.

## 8. Cómo reproducirlo
- Repositorio: <https://github.com/daralaz77/q-crypto-evolve>, commit `ace04e1`.
- Demostración en un comando: `examples/quickstart.py` (salida en `examples/SALIDA_ESPERADA.txt`).
- Emulador independiente: `pip install git+https://github.com/daralaz77/q-crypto-evolve` y `qce-kme`.
- Paquete de revisión: `python -m qce review-package` (release `b3dfc708179da391`), con guía en `REPRODUCCION.md`.
- Incidentes: `learning/incidents.jsonl`. Contraste con `qkdsec`: `docs/ETSI014_ADAPTER.md`.

## 9. Qué pedimos
- **Una persona revisora independiente** que firme G5 sobre el puente TLS, el HSM y el cliente ETSI 014.
- **Acceso temporal a un KME real** para repetir las pruebas y publicar un informe de interoperabilidad abierto, con lo que difiera.
- **Críticas.** Si encuentras un defecto, dínoslo: `SECURITY.md` explica cómo.
