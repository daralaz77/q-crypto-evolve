# Ruta de endurecimiento y mejora de efectividad

Estado de partida (2026-10-27): puertas G1–G4 y G6 pasan sobre el `release_id` b3dfc708179da391; 612 pruebas, 33/33 incidentes resueltos; G5 (revisión humana independiente) pendiente. Todo lo de esta ruta sale de brechas **ya declaradas** en `LIMITATIONS.md` y `THREAT_MODEL.md` o de la auditoría del Consejo 5X; nada es una conjetura nueva.

## Regla que ordena todo

Cada cambio en `qce/`, `tests/`, `gates.json` o los locks **cambia el `release_id`**, invalida la firma de G6 y obliga a repetir las puertas (~64 min). Por eso:

1. Lo que **no** cambia el `release_id` (documentos, CI, configuración de GitHub) se hace ya y por separado.
2. Lo que sí lo cambia se agrupa en **un solo paquete** (Fase 2) y se aplica **después** de tener un revisor humano, para firmar una vez y no cuatro.

Cada ítem tiene su prueba de validación. Un ítem sin prueba que falle al romper el control no cuenta como hecho (la regla del modelo de amenazas).

## Fase 0 — Sin tocar `release_id` (hacer ya)

| Ítem | Qué | Validación | Estado |
|---|---|---|---|
| 0.1 | Dependabot de alertas y de versiones | `gh api` devuelve `enabled`; llega un PR de prueba | Hecho 2026-10-27 |
| 0.2 | Informe y citas al día (v1.1, DOI de concepto) | Zenodo muestra v1.1; README y CITATION citan 23583891 | Hecho 2026-10-27 |
| 0.3 | Contactos para revisión humana (G5) | Mensajes 2–7 y 9 enviados | Hecho; esperar respuestas |
| 0.4 | Medir cuánto tarda cada puerta y qué parte es la mutación | Tabla de tiempos por puerta en `benchmarks/` | Hecho (`benchmarks/TIEMPOS_PUERTAS.md`) |
| 0.5 | Ejecutar la mutación en CI como trabajo aparte (semanal), sin bloquear cada push | Trabajo programado verde con puntuación 1.0 | Flujo creado. El primer intento (6 trabajadores, 120 s) abortó tras 1 h 51 min: el canario salió «detectado». Diagnóstico en CI: 6 copias del canario en paralelo tardan ~220 s (>120 s) y 1 de 6 falló por INC-0034. Con 3 trabajadores, 900 s y TMPDIR aislado (`benchmarks/mutation_ci.py`) las 6 copias pasan (~137 s). **Primera ejecución completa en CI (2026-10-29, 2 h 26 min): puntuación 0,9478 con 20 supervivientes, todos explicados:** 18 son `hsm-*` (sus pruebas se saltan sin el laboratorio SoftHSM + proveedor PKCS#11; ahora se excluyen de forma explícita y se listan) y 2 son `tls-client/server-min-version-off` (en Debian 13 la configuración de OpenSSL de qce ya fija TLS 1.3 como mínimo y la prueba mide el atributo; el comportamiento lo cubre la atestación). La puerta G3 local sigue siendo la que cuenta para la firma |

## Fase 1 — Preparar el terreno (cambios pequeños, aún sin aplicar)

Escribir los cambios en una rama y **no** fusionarlos a `main` hasta la Fase 2. Se mide en la rama; así el `release_id` firmado no se toca.

| Ítem | Qué | Por qué (evidencia) | Validación |
|---|---|---|---|
| 1.1 | Fijar con hash las dependencias de prueba (`pytest`, `hypothesis`) | `LIMITATIONS.md`: «las dependencias de prueba no están fijadas con hash»; T13 sin prueba offline | Prueba offline que falla si un hash no coincide; **Hecho en la rama `exp/fase1-endurecimiento`** (`requirements-test.hashes.txt`, CI con `--require-hashes`, 4 pruebas offline con canario). |
| 1.2 | Límite de tasa y anti-DoS por origen en el handshake y en QIL1 | T5 «SIN PRUEBA»; QIL1 permite retener una clave hasta `HANDSHAKE_TIMEOUT` sin límite por origen | Prueba de carga: N intentos por segundo desde un origen se rechazan; el tráfico legítimo pasa; **Hecho en la rama** (`qce/core/ratelimit.py`, aplicado antes del apretón TLS y antes de reservar claves en QIL1; con inundación real: 10 de 12 conexiones cortadas, 3 apretones frente a 13 sin límite). Es defensa de capa de aplicación: no sustituye a una protección de red. |
| 1.3 | Fuzzing guiado por cobertura (p. ej. Atheris) del parser y de los puentes `ctypes` | `FUZZ_Y_CARGA.md`: «fuzzing no guiado por cobertura» | Corpus semilla; 0 caídas en un periodo fijado; mutante que desactiva un límite del parser se detecta; **Hecho en la rama** (fuzzer propio guiado por cobertura con `sys.monitoring`, sin dependencias; 0 caídas en 6.000 ejecuciones del parser; canarios: halla un fallo escondido que la mutación a ciegas no halla y detecta 2 controles quitados). **No** fuzzea los puentes `ctypes` ni es AFL++/libFuzzer. |
| 1.4 | Rotación automática (planificador) y OCSP/CRL con distribución | `LIMITATIONS.md`: hay que llamar a `rotate_if_due`; sin OCSP; sin `crl_file` el cliente no comprueba | Prueba con reloj simulado: el certificado vencido se rota sin llamada manual; **Parcial en la rama**: planificador de rotación (`qce/transport/rotation.py`, 8 pruebas con reloj simulado e hilo real). **OCSP y distribución de CRL siguen pendientes.** |
| 1.5 | Guardar `min_epoch` del almacén fuera del vault | T9: responsabilidad del operador | Prueba: restaurar un vault antiguo con el `min_epoch` externo falla; **Hecho en la rama** (`EpochAnchor`, `save_anchored`/`load_anchored`; una copia antigua del vault se rechaza; canario sin ancla). |
| 1.6 | Firmar cada transición del workflow con la clave del actor | `LIMITATIONS.md`: `role` y `actor_id` se afirman, no se autentican | Prueba: una transición sin firma válida se rechaza; **Hecho en la rama** (`Workflow(actor_keys=…)`: cada transición lleva la firma híbrida del actor, ligada a la cabeza del registro; 5 pruebas con canarios). Opcional: sin `actor_keys` el comportamiento sigue igual. |
| 1.8 | Dar a `tests/test_tls_custody.py::test_server_works_and_no_private_key_ever_sits_in_a_file` un TMPDIR propio (mide el /tmp compartido y falla si otro proceso crea un `qce-key-*` a la vez) | INC-0034: **resuelto en `main`** (TMPDIR propio por escenario; prueba de regresión que falla sin el arreglo) | Prueba que lanza dos procesos a la vez y no falla; la prueba original sigue fallando si queda un directorio propio sin borrar |
| 1.11 | **INC-0035:** que las pruebas de NSS (`nss_server`) no dependan de que `localhost` resuelva a IPv4 (arrancar `selfserv` con dirección explícita o sondear ambas familias) | INC-0035, abierto: fallan 2 pruebas en una red solo IPv4 | Pasa en redes con y sin IPv6; cambia `tests/` (nueva firma de G6) |
| 1.9 | Triadas el 2026-10-29: las 2 alertas CodeQL `py/insecure-protocol` de `qce/transport/tls13.py` (98 y 275) vienen de `_attest()`, cuyos contextos de autodiagnóstico NO fijan `minimum_version` a propósito (sobre 127.0.0.1, PKI efímera) para probar que un cliente limitado a TLS 1.2 no conecta; los contextos reales (`server_context`/`client_context`) sí fijan TLS 1.3. Cerradas como «used in tests» con ese comentario; sin cambio de código | CodeQL, 2026-10-29 | Hecho |
| 1.10 | **Autenticación ML-DSA en el transporte TLS 1.3** (certificados ML-DSA-65/87 en `qce/transport/pki.py` y `custody.py`) | Brecha B1 de `COMPARATIVA_PQC.md`: hoy los certificados son ECDSA P-256 y solo el intercambio de claves es poscuántico. Prototipo en la rama `exp/mldsa-transport` (commit 5998876): 14 pruebas, CI verde, **sin** puertas, mutación ni revisión | Recuperar la rama sobre el código de la Fase 2; añadir mutantes para `signing_hash` y `new_private_key`; probar NSS y GnuTLS con certificados ML-DSA; medir latencia; decidir si ML-DSA-65 o -87 es el valor por defecto (mensajes del servidor 10.155 B frente a 13.431 B, contra 1.794 B con ECDSA) |
| 1.7 | Hacer observable el descarte de la clave KEM efímera | T19 sin prueba (mutante declarado equivalente) | Prueba que falla si la clave sigue accesible tras el handshake; **Hecho en la rama** (`HybridKemPrivateKey.destroy()` y `destroyed`; el servidor lo llama aunque el apretón falle; el descarte sigue siendo de mejor esfuerzo en Python). |

> **Estado (2026-10-30):** los ítems 1.1–1.7 están implementados en la rama `exp/fase1-endurecimiento` (commit f6ab343): 652 pruebas pasan en local (fallan solo las 2 de NSS por INC-0035) y el CI es verde en x86_64 y arm64. **No hay** puertas, mutación ni mutantes nuevos para ese código, ni revisión humana. Los controles nuevos cubiertos por canarios de pruebas, no por la prueba de mutación (G3): añadir mutantes es trabajo pendiente.

## Fase 2 — Paquete único y revisión humana (G5)

1. Esperar a tener **un revisor humano** (respuesta a los mensajes 4/5, cotización del 7 u OSTIF).
2. Que el revisor mire primero el código **actual** (el `release_id` firmado) o, si prefiere, la rama de la Fase 1: lo más barato es que revise una sola versión.
3. Fusionar el paquete de la Fase 1 junto con los hallazgos del revisor, **en un solo cambio**.
4. Repetir `qce gates` (~64 min), pedir la firma de G5 al revisor y la de G6 a ti. Resultado esperado: `RELEASE_APPROVED` solo con las dos firmas humanas; el sistema nunca lo simula.

Criterio de salida: G1–G6 en `pass` sobre el mismo `release_id`, con el informe del revisor enlazado.

## Fase 3 — Contrastar con el mundo real

| Ítem | Qué | Condición |
|---|---|---|
| 3.1 | Probar el cliente ETSI 014 contra un KME real y publicar un informe de interoperabilidad con lo que difiera (mensaje 6) | Acceso concedido por un fabricante o laboratorio |
| 3.2 | Ejecutar el kit de HSM en la nube (`docs/hsm_cloud/`) | Cuenta de Google Cloud y presupuesto menor; el kit nunca se ejecutó contra Google |
| 3.3 | Segunda implementación del híbrido en el sentido servidor NSS con PSK | Cuando NSS lo permita (`selfserv` no aplica la PSK hoy) |
| 3.4 | Pruebas cruzadas con otros emuladores (mensajes 2/3) | Respuesta de QuantumUPB o TUe-QTS |

## Fase 4 — Efectividad (que mejore más rápido y con menos fricción)

| Ítem | Qué | Medida de éxito |
|---|---|---|
| 4.1 | Mutación incremental: solo los mutantes de los archivos que cambiaron, y la completa en CI semanal | Puertas de un cambio pequeño en minutos en vez de ~64 min; G3 completa sigue exigida antes de firmar |
| 4.2 | Cada incidente nuevo se convierte en prueba de regresión y en mutante (ya se hace; automatizar el recordatorio) | Ningún incidente `resuelto` sin `reproduction_test` (ya lo exige el libro) |
| 4.3 | Atacar las causas repetidas: 18 incidentes de «código» y 9 de «prueba insuficiente» | Revisión de diseño por causa; tendencia de incidentes por semana a la baja |
| 4.4 | Más contraste independiente: otra herramienta de terceros además de `qkdsec` | Al menos un hallazgo o una confirmación nueva; los 2 defectos de `qkdsec` salieron de aquí |

## Fase 5 — Garantías formales (solo si hay revisor y presupuesto)

- Modelo computacional (no solo simbólico) del handshake `QCE1` y de `QIL1`, y conformidad modelo-código. Hoy: Tamarin simbólico, sin capa de registros ni KCI estricto.
- Medición de canales laterales en el puente `ctypes` y el código de control (hoy no es de tiempo constante).
- Si el objetivo pasa a ser FIPS 140-3 / CNSA 2.0: módulo OpenSSL validado (3.5.8 está en revisión del CMVP) y rediseño del híbrido sin X25519. No se afirma nada de esto hoy.

## Qué NO hacer

- No declarar el sistema listo para datos reales mientras G5 siga omitida y el handshake propio (`QCE1`) y la capa `QIL1` no tengan revisión humana.
- No firmar G5/G6 por el revisor ni por ti sin leer el informe.
- No relajar umbrales (`gates.json`) para que una puerta pase.
- No mezclar cambios de código sueltos antes de la Fase 2: cada uno invalida la firma.

## Orden recomendado

`0.4 → 0.5` (ya, sin riesgo) → esperar revisor mientras se escribe la rama de la Fase 1 (`1.1`, `1.2`, `1.3` primero: son los de mayor riesgo cubierto) → Fase 2 → `3.1` cuando haya KME → `4.1` en paralelo desde el principio.

Los tiempos y costos exactos se desconocen hasta recibir cotizaciones; esta ruta no los inventa.
