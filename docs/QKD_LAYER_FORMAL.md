# QIL1 — modelo formal (Tamarin) y sus límites

**Archivos:** `formal/qil1.spthy` (modelo), `formal/expected_qil1.json` (veredictos esperados por configuración), `qce/evolve/formal.py` (ejecutor y mutantes del modelo; `python -m qce formal` los corre junto con los de QCE1).
**Estado: NO REVISADO por terceros.** Herramienta: Tamarin Prover 1.12.0. Los veredictos de abajo son salida real de esa herramienta en este equipo; no son una prueba de seguridad de la implementación.

## 1. Qué se modela

El apretón de la capa (HELLO, ACCEPT, CONFIRM, `docs/QKD_LAYER_SPEC.md` §5) sobre un **canal TLS abstracto**: cada sesión TLS aporta a sus dos extremos un valor de ligadura `bind` y la huella `cert(S)` del certificado del servidor.
El atacante controla toda la red **fuera** de TLS y además:

- siempre puede abrir **su propia** sesión TLS hacia el servidor como cliente (TLS aquí no autentica clientes);
- con `-DBREAKTLS` puede terminar la sesión del cliente con un certificado falso (`cert('rogue')`) y leer, escribir y retransmitir dentro de ella (**TLS roto de cara al cliente**);
- con `-DREVEALQKD` puede obtener la clave QKD de cualquier id.

La clave QKD es un hecho *lineal*: cada extremo la consume una sola vez. Las funciones `h`, `mac`, `kdfc`, `kdf1`, `kdf2` son oráculos aleatorios inyectivos.

## 2. Lemas

| Lema | Dice | Papel |
|---|---|---|
| `executable` | existe una ejecución completa | sanidad |
| `rogue_relay_reaches_done` | existe una ejecución en que el cliente termina contra un servidor falso | **sanidad del ataque**: debe ser falso con la ligadura y cierto sin ella o con la clave revelada |
| `secrecy_c2s`, `secrecy_s2c` | las claves de la capa no las conoce el atacante, salvo si se reveló la clave QKD | Q1 |
| `agreement` | si el cliente termina, el servidor inició un apretón con el mismo `th` | Q3 |
| `channel_agreement` | …y en **la misma sesión TLS** (mismo `bind` y huella) | Q2 |
| `server_agreement` | si el servidor termina, un cliente terminó con las mismas claves y la misma sesión | Q3 |
| `client_authenticated_by_qkd` | el servidor solo termina con quien inició un apretón con esa clave | Q3 |
| `key_single_use` | dos apretones del servidor con la misma clave solo si el primero abortó y la devolvió (reserva exclusiva) | Q4 |
| `no_reuse_after_done` | tras completar un apretón no hay más apretones con esa clave | Q4 |
| `later_qkd_leak_exposes_past_session` | exists-trace de **límite**: una filtración posterior de la clave expone una sesión pasada | medida de la confidencialidad pasada |

## 3. Resultados (verificados 2026-10-17 con Tamarin 1.12.0; 8 configuraciones en `formal/expected_qil1.json`)

Todos los lemas «all-traces» se **verifican** en las 8 configuraciones salvo `channel_agreement` y `server_agreement` en `nobind_breakTLS` y `nobind_revealQkd_breakTLS`. Los exists-trace:

| Configuración | `rogue_relay_reaches_done` | `later_qkd_leak_exposes_past_session` | Lectura |
|---|---|---|---|
| `base`, `breakTLS`, `revealQkd`, `nobind`, `nobind_revealQkd` | falso | falso | sin la combinación TLS roto + sin ligadura, el ataque de retransmisión no existe; una filtración posterior de `K` no expone sesiones pasadas porque `th` incluye un valor de ligadura secreto |
| `revealQkd_breakTLS` | **verdadero** | falso | con la clave revelada **antes** y TLS roto, el atacante se hace pasar por el servidor; el pasado sigue protegido (la ligadura de las sesiones honestas es secreta) |
| `nobind_breakTLS` | **verdadero** | falso | **sin la ligadura, el MITM con certificado falso funciona** (`channel_agreement`, `server_agreement` falsificados): lo que demuestra que el modelo tiene dientes |
| `nobind_revealQkd_breakTLS` | **verdadero** | **verdadero** | sin ligadura, con TLS roto y `K` filtrada después, el pasado queda expuesto |

Lectura honesta: con TLS roto y `K` secreta, el secreto y la autenticación se mantienen (razón de ser de la capa). Si el atacante además tiene `K`, la capa no protege hacia delante. La confidencialidad pasada ante una filtración posterior de `K` descansa en que el valor de ligadura de TLS siga siendo secreto (la ligadura es lo que lo consigue).

**Cota del modelo.** El aborto con devolución de la clave crea ciclos (reservar → abortar → reservar…) y Tamarin no termina; la restricción `AtMostOneAbortPerKey` la acota a **un aborto por clave**. Los lemas de reserva se prueban para claves que abortan 0 o 1 vez, no para un número arbitrario. Declarado: la propiedad para abortos ilimitados **no está probada**; la cubre solo la conformidad con trazas reales (`docs/QKD_LAYER_CONFORMANCE.md`).

## 4. Mutantes del modelo (deben hacer caer el lema indicado)

| Mutante | Cae |
|---|---|
| el servidor no comprueba la etiqueta del cliente | `client_authenticated_by_qkd`, `server_agreement` |
| el cliente no comprueba la etiqueta del servidor (con `BREAKTLS`) | `agreement` |
| la clave QKD es reutilizable | `key_single_use` |
| la clave vuelve a estar disponible tras completar | `no_reuse_after_done` |
| las claves internas se derivan sin la clave QKD (con `NOBIND`+`BREAKTLS`) | `secrecy_c2s`, `secrecy_s2c` |

Hallazgo durante el trabajo: sin `BREAKTLS`, el secreto de las claves de la capa se cumple aunque no usen la clave QKD, porque el valor de ligadura de una sesión honesta es secreto para el atacante; solo con TLS roto se ve la contribución de la clave QKD. El mutante necesita por eso `NOBIND`+`BREAKTLS`.

## 5. Qué NO cubre

- La **capa de registros** (AEAD, contadores): se prueba con pruebas de ejecución, no con el modelo.
- La seguridad de **TLS**: se supone un canal abstracto; no se modela el calendario de claves de TLS 1.3 ni que `tls-unique` sea realmente único y secreto en TLS 1.3 (supuesto declarado en la especificación §3 y §10).
- La **física de QKD** y la calidad de la clave: es un valor fresco secreto.
- Codificaciones y longitudes (términos inyectivos), canales laterales, denegación de servicio (gasto de claves, spec §9).
- **KCI en sentido estricto, compromiso del estado efímero**, revelación de claves de sesión, rotura parcial o escalonada (solo hay dos escenarios de rotura: TLS y clave QKD, ambas totales).
- **Unknown-key-share y varios servidores**: hay un solo servidor en el modelo. Lo que sí está: la independencia entre claves (las excepciones de los lemas son por identificador: revelar otra clave no cambia nada) y que `ch` (la huella del certificado) entra en `th`.
- Conformidad código ↔ modelo: ver `docs/QKD_LAYER_CONFORMANCE.md` (trazas de ejecución, no prueba del código).
