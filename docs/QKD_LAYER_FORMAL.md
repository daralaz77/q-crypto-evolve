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
| `key_single_use` | no hay dos apretones del servidor con la misma clave | Q4 |

## 3. Resultados (verificados 2026-10-17 con Tamarin 1.12.0)

Todos los lemas se **verifican** salvo lo señalado:

| Configuración | Resultado |
|---|---|
| `base` (TLS íntegro) | todos verificados; `rogue_relay_reaches_done` falsificado (no hay trazas del ataque) |
| `breakTLS` (certificado falso aceptado) | todos verificados, incluida `channel_agreement`; `rogue_relay_reaches_done` falsificado: **la ligadura frena la retransmisión** |
| `revealQkd` | verificados (la excepción «salvo clave revelada» los hace triviales); relay falsificado |
| `revealQkd_breakTLS` | verificados por la misma excepción; `rogue_relay_reaches_done` **verificado**: con la clave revelada y TLS roto el atacante sí se hace pasar por el servidor |
| `nobind` (mutante: se quita la ligadura de la derivación) | todo igual que `base`, porque sin TLS roto no hay atacante en medio |
| `nobind_breakTLS` | `channel_agreement` y `server_agreement` **falsificados** y `rogue_relay_reaches_done` verificado: **sin la ligadura, el MITM con certificado falso funciona**. Es lo que demuestra que el modelo tiene dientes |

Lectura honesta: con TLS roto y la clave QKD secreta, el secreto y la autenticación se mantienen (esa es la razón de ser de la capa). Si el atacante además tiene la clave QKD, la capa no protege.

## 4. Mutantes del modelo (deben hacer caer el lema indicado)

| Mutante | Cae |
|---|---|
| el servidor no comprueba la etiqueta del cliente | `client_authenticated_by_qkd`, `server_agreement` |
| el cliente no comprueba la etiqueta del servidor (con `BREAKTLS`) | `agreement` |
| la clave QKD es reutilizable | `key_single_use` |
| las claves internas se derivan sin la clave QKD (con `NOBIND`+`BREAKTLS`) | `secrecy_c2s`, `secrecy_s2c` |

Hallazgo durante el trabajo: sin `BREAKTLS`, el secreto de las claves de la capa se cumple aunque no usen la clave QKD, porque el valor de ligadura de una sesión honesta es secreto para el atacante; solo con TLS roto se ve la contribución de la clave QKD. El mutante necesita por eso `NOBIND`+`BREAKTLS`.

## 5. Qué NO cubre

- La **capa de registros** (AEAD, contadores): se prueba con pruebas de ejecución, no con el modelo.
- La seguridad de **TLS**: se supone un canal abstracto; no se modela el calendario de claves de TLS 1.3 ni que `tls-unique` sea realmente único y secreto en TLS 1.3 (supuesto declarado en la especificación §3 y §10).
- La **física de QKD** y la calidad de la clave: es un valor fresco secreto.
- Codificaciones y longitudes (términos inyectivos), canales laterales, denegación de servicio (gasto de claves, spec §9).
- **Unknown-key-share, KCI, compromiso del estado efímero**, revelación de claves de sesión, rotura parcial o escalonada (solo hay dos escenarios de rotura: TLS y clave QKD, ambas totales).
- Conformidad código ↔ modelo: **no se ha hecho** para QIL1 (QCE1 sí la tiene, `docs/QCE1_CONFORMANCE.md`). Las pruebas anclan la especificación al código, no el modelo al código.
