# QIL1 — capa interna con clave QKD sobre TLS 1.3 (especificación)

**Versión:** QIL1 (`QIL1`) · **Estado: NO REVISADA por terceros** · **Código:** `qce/transport/qkd_layer.py` · **Modelo:** `formal/qil1.spthy`
**Propósito:** que un revisor pueda evaluar esta capa sin leer Python. **Qué NO es:** no es un estándar, no está revisada por ninguna persona experta,
no sustituye a la opción A de `docs/QKD_TLS_OPTIONS.md` (clave QKD como PSK externa dentro del propio TLS 1.3, que hoy no es posible desde Python)
y no es una prueba de seguridad. La claim es solo esta: *dentro de este modelo y con estos supuestos, las propiedades de §7 se cumplen*.
Toda la autoría (código, especificación, modelo, pruebas) es de instancias de Claude; ninguna persona la ha revisado.

## 1. Por qué existe y qué es

Ninguna pila TLS disponible aquí (Python 3.14 `ssl` sobre OpenSSL) permite una PSK externa en TLS 1.3, así que la clave QKD no puede entrar en el calendario de claves
de TLS. QIL1 la aplica **dentro** del canal TLS ya establecido: cliente y servidor derivan claves nuevas a partir de la clave QKD, **ligadas a esa sesión TLS**,
se confirman mutuamente que la poseen y cifran los datos de aplicación con una segunda capa AEAD. El resultado es una **cascada** de dos cifrados independientes
(TLS 1.3 híbrido X25519MLKEM768 por fuera, QIL1 por dentro). **No** es un combinador dentro del calendario de claves de TLS: si se rompen las dos capas, se rompe todo;
si se rompe una sola, la otra sigue protegiendo.

| Objetivo (a verificar) | Cómo |
|---|---|
| Q1. Confidencialidad aunque TLS esté roto (incluida una CA o un certificado falso aceptado) | Las claves de la capa dependen de la clave QKD secreta (§4) |
| Q2. Ligar la capa a LA sesión TLS: un atacante que termine TLS con un certificado falso y retransmita al servidor real falla | `th` incluye el valor de ligadura TLS y la huella del certificado del servidor (§4) |
| Q3. Autenticación mutua por posesión de la clave QKD | Dos etiquetas MAC con una clave de confirmación derivada (§5) |
| Q4. Un solo uso de cada clave QKD | El servidor la consume al recibir el HELLO (§6) |
| Q5. Integridad, orden y no reflexión de los registros | AEAD con contador como nonce, una clave por dirección, `th` en el AAD (§8) |

No objetivos: autenticar al cliente por identidad (solo por posesión de la clave QKD), anonimato del identificador de clave frente a quien rompa TLS, protección
frente a gasto de claves por un tercero que conozca un identificador (§9), seguridad de la propia clave QKD (la aporta el dispositivo; aquí es una **simulación**,
ver `LIMITATIONS.md`), canales laterales.

## 2. Notación

`‖` concatenación. `lp(x)` = longitud de `x` en 4 bytes big-endian ‖ `x`. `H` = SHA-256. `MAC(k, m)` = HMAC-SHA-256. `HKDF(k, salt, info)` = HKDF-SHA-256 (RFC 5869) con
longitud de salida de 32 bytes. Todos los literales son ASCII. `K` es la clave QKD (entre `QKD_KEY_MIN` y `QKD_KEY_MAX` bytes), `kid` su identificador (entre 1 y `KEY_ID_MAX` bytes).

## 3. Entradas procedentes de TLS

La capa solo se ejecuta sobre una conexión **TLS 1.3 ya establecida y autenticada por el cliente contra su ancla de confianza** (`qce.transport.tls13`, `X25519MLKEM768`).
De ella toma dos valores:

- `bind` = valor de canal `tls-unique` de la conexión (en TLS 1.3 con OpenSSL son 48 bytes; **no es** el exportador estándar RFC 9266, que Python no expone: ver §10, pregunta 1).
  Debe tener al menos `BIND_MIN` bytes; si no existe, la capa **no** se abre.
- `cert_fp` = `H(DER del certificado del servidor)`. El cliente lo lee del par; el servidor lo recibe como parámetro (conoce su propio certificado).

Si la versión negociada no es `TLSv1.3` la capa no se abre.

## 4. Derivación

```
nc, ns   = 32 bytes aleatorios (cliente, servidor)
th       = H( lp("QIL1/th") ‖ lp(bind) ‖ lp(cert_fp) ‖ lp(kid) ‖ lp(nc) ‖ lp(ns) )
conf     = HKDF(K, salt = th, info = "QIL1/conf")
k_c2s    = HKDF(K, salt = th, info = "QIL1/c2s")
k_s2c    = HKDF(K, salt = th, info = "QIL1/s2c")
```

Una clave por propósito, con `info` distinto. `th` es a la vez la sal y parte del contexto de cada etiqueta, de modo que cualquier cambio en la sesión TLS, el certificado,
el identificador o los nonces cambia todas las claves.

## 5. Mensajes (cada uno es un «frame»: longitud de 4 bytes big-endian ‖ contenido; máximo `tls13.MAX_FRAME`)

| # | Sentido | Contenido |
|---|---|---|
| 1 HELLO | C→S | `"QIL1"` ‖ `len(kid)` (1 byte) ‖ `kid` ‖ `nc` (32 bytes). Longitud total exacta; versión exacta; `1 ≤ len(kid) ≤ KEY_ID_MAX` |
| 2 ACCEPT | S→C | `ns` (32 bytes) ‖ `ts`, con `ts = MAC(conf, "server" ‖ th)` (32 bytes) |
| 3 CONFIRM | C→S | `tc = MAC(conf, "client" ‖ th ‖ ts)` (32 bytes) |

El cliente verifica `ts` (comparación de tiempo constante) **antes** de enviar `tc`; si no coincide, se cierra sin enviar nada. El servidor verifica `tc` antes de abrir
la capa. Tras un fallo en cualquier punto la conexión se descarta; el servidor **no** envía mensajes de error al par (sin oráculo).

## 6. Servidor: reserva, confirmación y liberación

El servidor obtiene `K` de una fuente con tres operaciones: `reserve(kid)` (entrega `K` o nada, y la marca como en uso: nadie más la obtiene), `commit(kid)` (la consume para siempre) y
`release(kid)` (la devuelve). Reserva al recibir un HELLO bien formado (regla `S1_accept` del modelo); **consume solo si el cliente demuestra poseerla** (`S2_done`); la **libera** si el apretón
falla o si el cliente no responde en `HANDSHAKE_TIMEOUT` segundos. Un HELLO malformado no toca la fuente. Si la fuente entrega material fuera de rango, se descarta (`commit`) y el apretón se aborta.
Con el `KeyBroker` real (`BrokerSource`): `hold` (reserva y entrega sin consumir), `consume` y `release`; falla cerrado ante política, cuarentena o consumidor no autorizado.
Consecuencias: quien solo conoce el identificador **no puede gastar la clave** (T43); un atacante que reserva y se queda callado la retiene como máximo `HANDSHAKE_TIMEOUT`; tras completar, la clave no vuelve a usarse.

## 7. Propiedades pretendidas (modelo `formal/qil1.spthy`, ver `docs/QKD_LAYER_FORMAL.md`)

1. **Secreto** de `k_c2s` y `k_s2c` mientras `K` no se revele, **aunque TLS esté roto** (`secrecy_c2s`, `secrecy_s2c`, verificadas con y sin `BREAKTLS`).
2. **Acuerdo** del cliente (`agreement`) y del servidor (`server_agreement`) sobre `th`, las claves y la sesión TLS.
3. **Ligadura al canal** (`channel_agreement`): lo que el cliente da por establecido, el servidor lo inició en **su misma sesión TLS** (mismo `bind` y mismo certificado).
   Con TLS roto, un atacante con certificado falso y retransmisión **no** logra completar; sin la ligadura (mutante `NOBIND`) sí (`rogue_relay_reaches_done`).
4. **Autenticación del cliente por la clave** (`client_authenticated_by_qkd`).
5. **Reserva exclusiva y un solo uso** (`key_single_use`, `no_reuse_after_done`): dos apretones del servidor con la misma clave solo si el primero abortó y la devolvió; tras completar no hay más.
6. **Límite medido** (`later_qkd_leak_exposes_past_session`, exists-trace): una filtración POSTERIOR de `K` no expone una sesión pasada mientras el valor de ligadura de TLS siga secreto; sí la expone si además TLS falla y no hay ligadura (`nobind_revealQkd_breakTLS`). Es decir, la confidencialidad pasada descansa en TLS y en `K` a la vez.

Lo que el modelo **no** cubre: la capa de registros AEAD (§8), la física de QKD, la seguridad del propio TLS (se modela como un canal abstracto con un valor de ligadura y una huella),
codificaciones y longitudes (los términos se tratan como inyectivos), canales laterales, denegación de servicio.

## 8. Capa de registros

AEAD ChaCha20-Poly1305. Una clave por dirección (`k_c2s` cliente→servidor, `k_s2c` servidor→cliente). Nonce = contador de la dirección, 12 bytes big-endian, empezando en 0, **implícito**
(no se envía). AAD = `"QIL1/rec"` ‖ `th`. Un registro que no autentica (manipulado, repetido, reordenado, de otra sesión o reflejado) es fatal: el receptor no avanza el contador y debe cerrar.
Máximo de `MAX_RECORDS` registros por dirección (`KeyStateError` al agotarse); máximo de texto en claro por registro: `tls13.MAX_FRAME − 16` bytes.

## 9. Límites y amenazas conocidas (no resueltas)

- **Retención de la clave.** Un atacante que conozca el identificador y reserve la clave sin completar la retiene hasta `HANDSHAKE_TIMEOUT`; en ese tiempo el cliente legítimo es rechazado. No hay límite de tasa por origen.
- **Valor de ligadura no estándar.** `tls-unique` en TLS 1.3 no está especificado (RFC 9266 desaconseja usarlo así): es el único valor disponible en Python 3.14. Si otra pila lo calcula distinto, no interoperan.
- **Cascada, no combinador.** Un atacante que rompa a la vez TLS **y** obtenga `K` rompe todo; QIL1 no añade protección contra quien robe `K` del dispositivo o del broker.
- **Sin secreto hacia adelante propio.** Las claves de la capa dependen de `K`, `th` y los nonces; `th` incluye el valor de ligadura de TLS. Si `K` se filtra más tarde pero TLS siguió siendo secreto, la sesión pasada no se expone (lema medido, §7.6); si TLS también se rompe (p. ej. con un ordenador cuántico futuro), cae. El secreto hacia adelante lo aporta TLS (KEM efímero). `K` es de un solo uso.
- **Material en memoria.** Sin HSM; la clave y las derivadas viven en memoria del proceso (`LIMITATIONS.md`).
- **QKD simulado.** El material de `K` proviene de un simulador (os.urandom); el enlace físico no está modelado ni probado.

## 10. Preguntas abiertas para el revisor

1. ¿Es aceptable `tls-unique` (48 bytes en OpenSSL/TLS 1.3, no estándar) como única ligadura, o hay un ataque de «triple apretón de manos» u otro que lo invalide en TLS 1.3?
2. `th` es sal y contexto a la vez, y el mismo `K` produce tres claves con `info` distintos y salida de 32 bytes: ¿es suficiente separación de dominios?
3. El servidor reserva `K`, la consume solo al verificar al cliente y la libera si falla (§6): ¿la ventana de retención hasta `HANDSHAKE_TIMEOUT` es aceptable, o hace falta un límite de tasa por origen?
4. La ligadura incluye la huella del certificado, pero el servidor la recibe como parámetro: ¿hay un camino en que el servidor use una huella distinta de la del certificado realmente presentado?
5. ¿Falta un lema de *unknown-key-share*, de KCI o de revelación de claves de sesión?

## 11. Constantes (ancladas al código por `tests/test_qkd_layer.py`)

```constants
VERSION = QIL1
TH_LABEL = QIL1/th
INFO_CONF = QIL1/conf
INFO_C2S = QIL1/c2s
INFO_S2C = QIL1/s2c
REC_AAD_LABEL = QIL1/rec
ROLE_CLIENT = client
ROLE_SERVER = server
NONCE_LEN = 32
TAG_LEN = 32
KEY_ID_MAX = 128
QKD_KEY_MIN = 32
QKD_KEY_MAX = 1024
BIND_MIN = 12
MAX_RECORDS = 4294967296
HANDSHAKE_TIMEOUT = 10.0
```

## 12. Cómo se comprueba que esta especificación es fiel al código

- `tests/test_qkd_layer.py::test_constants_table_matches_code` — la tabla de §11 frente a las constantes reales.
- `tests/test_qkd_layer.py::test_independent_rederivation_matches_a_real_session` — ejecuta un apretón real sobre TLS 1.3 con una clave QKD de prueba y, **solo con las fórmulas de este documento**,
  recalcula `th`, las dos etiquetas y las claves, y descifra un registro con ChaCha20-Poly1305 directo.
- `tests/test_qil_conformance.py` — trazas del código real con atacante activo contra los lemas y las guardas del modelo (`docs/QKD_LAYER_CONFORMANCE.md`).
- Escenarios hostiles (clave equivocada, reutilización, MITM con certificado falso, HELLO malformado, manipulación, repetición, reflexión, reordenación): `tests/test_qkd_layer.py`.
- Lo que **no** comprueba: que el modelo sea fiel más allá de las trazas observadas, ni propiedades de seguridad (para eso son el modelo y la revisión externa, que **no** ha ocurrido).
