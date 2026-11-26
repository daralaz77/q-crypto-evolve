# Sobre poscuántico con quórum: especificación byte a byte (formato de archivo 3, solicitudes 4)

Estado: **laboratorio**, sin revisión externa; puede cambiar sin compatibilidad hacia atrás. Palabras DEBE / NO DEBE en sentido normativo.
Código: `qce/sealed/`. Vectores: `tests/sealed_vectors/` (las claves salen de etiquetas: ver `tests/sealed_vector_cases.py`). Segundo lector escrito desde este documento: `tests/sealed_reader.py`. Uso y límites: [`SEALED_ENVELOPE.md`](SEALED_ENVELOPE.md).

## 1. Notación
- `‖` concatenación. `u32(n)`: 4 bytes big-endian. `u64(n)`: 8 bytes big-endian. `lp(x) = u32(len(x)) ‖ x`.
- `H(a, b, …) = SHA-256(lp(a) ‖ lp(b) ‖ …)`.
- `HKDF(ikm, info)`: HKDF-SHA256 (RFC 5869), sin sal, 32 bytes de salida.
- `AEAD0(clave, claro, aad)`: AES-256-GCM con nonce de 12 bytes a cero. SOLO con claves de un único uso (derivadas de un secreto KEM fresco).
- Base64: alfabeto estándar con relleno, en forma canónica (decodificar y volver a codificar da la misma cadena). Hexadecimal: minúsculas.
- Los textos entre comillas en las fórmulas son bytes ASCII.

## 2. Algoritmos por nivel

| Nivel | KEM (`kem`) | Clave pública / texto cifrado | Firma híbrida | Clave pública / firma |
|---|---|---|---|---|
| `standard` | `X-Wing-draft11` | 1216 / 1120 | Ed25519 + ML-DSA-65 | 1984 / 3373 |
| `high` | `QCE-X25519-MLKEM1024` | 1600 / 1600 | Ed25519 + ML-DSA-87 | 2624 / 4691 |

El nivel fija el KEM y la firma: no hay negociación. El nivel de todas las claves de un archivo es el de la clave del emisor.

### 2.1 X-Wing
Según draft-connolly-cfrg-xwing-kem-11 (borrador IETF, no es un RFC). Semilla privada de 32 bytes `sk`; `e = SHAKE256(sk, 96)`; ML-KEM-768 desde la semilla `d‖z = e[0:64]`; clave X25519 `e[64:96]`.
`pk = pk_M(1184) ‖ pk_X(32)`; `ct = ct_M(1088) ‖ ct_X(32)`; `ss = SHA3-256(ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ 5c2e2f2f5e5c)`.

### 2.2 QCE-X25519-MLKEM1024 (combinador propio, sin revisión externa)
Semilla privada de 96 bytes: X25519 (32) ‖ `d‖z` (64). `pk = pk_X(32) ‖ pk_M(1568)`; `ct = ct_X(32) ‖ ct_M(1568)`.
`ss = HKDF(ss_M ‖ ss_X, "QCE1/hybrid-kem/X25519+ML-KEM-1024" ‖ ct ‖ pk)`.

### 2.3 Firma híbrida `Firma(contexto, mensaje)`
Semilla privada de 64 bytes: Ed25519 (32) ‖ semilla ML-DSA `xi` (32). `pk = pk_Ed(32) ‖ pk_MLDSA`.
`sig = Ed25519(contexto ‖ 00 ‖ mensaje) (64) ‖ ML-DSA(mensaje, contexto)`. Verificar DEBE exigir **las dos**.
Huella de una clave pública: `id = SHA-256(pk)`.

## 3. Archivo

```
archivo = prefijo ‖ firma_cabecera ‖ cuerpo ‖ firma_archivo
prefijo = MAGIC ‖ u32(len(cabecera)) ‖ cabecera          MAGIC = 51 53 45 4c 03 00   ("QSEL", 03, 00)
D = SHA-256(prefijo)                                       (identifica el archivo)
firma_cabecera = Firma("QSEL3/header", prefijo)
firma_archivo  = Firma("QSEL3/file", D ‖ SHA-256(cuerpo) ‖ u64(len(cuerpo)))
```
`2 ≤ len(cabecera) ≤ 1 048 576`. El cuerpo ocupa todo lo que queda entre las dos firmas (al menos 16 bytes).
El lector DEBE conocer la clave pública del emisor por un canal propio (nunca la toma del archivo), DEBE verificar `firma_cabecera` **antes** de interpretar la cabecera, y DEBE verificar `firma_archivo` antes de entregar participaciones o publicar contenido.

### 3.1 Cabecera
Objeto JSON en UTF-8. El escritor usa claves ordenadas, sin espacios y sin escapar caracteres no ASCII; el lector verifica la firma sobre los bytes tal como están. El lector DEBE rechazar claves repetidas en cualquier objeto, campos de más o de menos, y booleanos donde se espera un entero.

| Campo | Tipo y reglas |
|---|---|
| `v` | entero 3 |
| `level` | `standard` o `high`; DEBE ser el de la clave del emisor |
| `kem` | el de la tabla de la sección 2 para `level` |
| `aead` | `AES-256-GCM` o `CHACHA20-POLY1305` (solo para el cuerpo) |
| `sid` | 32 bytes aleatorios, hex |
| `sender` | huella de la clave del emisor, hex; DEBE coincidir con la usada para verificar |
| `openers` | lista de 1 a 8 huellas (hex) de claves de **firma** autorizadas a pedir la apertura |
| `need` | entero 1…número de grupos |
| `groups` | lista de 1 a 8 grupos `{name, k, com, members}` |
| `commit` | `H("QSEL3/key", sid, K)`, hex |
| `locks` | lista de 0 a 4 candados `{id, label, com}`: `id` 16 bytes en hex, sin repetir; `label` imprimible de 1 a 64; `com = H("QSEL3/lock", sid, id, clave_por_archivo)` (`id` en bytes) |

Grupo: `name` de 1 a 64 caracteres imprimibles (ninguno de las categorías Unicode C* ni Z*, salvo el espacio U+0020); `members` de 1 a 16 `{id, ct, box, com}`; `k` entero 1…número de miembros; `com = H("QSEL3/group", sid, u32(g), s_g)`.
Miembro: `id` huella de su clave KEM (hex); `ct` (base64, longitud del texto cifrado KEM); `box` (base64, 48 bytes); `com` (hex). Una misma `id` NO DEBE aparecer dos veces en el archivo.
Los grupos y los miembros se numeran desde 1 en el orden de las listas (`g`, `x`).

### 3.2 Resguardo
Permite decidir sobre un archivo sin tener su cuerpo:
```
resguardo = "QSELSTUB" ‖ prefijo ‖ firma_cabecera ‖ SHA-256(cuerpo) ‖ u64(len(cuerpo)) ‖ firma_archivo
```
Las dos firmas son las del archivo. El lector DEBE verificarlas igual (la del archivo, sobre la huella y longitud declaradas), DEBE exigir el tamaño exacto y `len ≥ 16`, y NO DEBE permitir abrir un resguardo. Custodios y guardián PUEDEN actuar sobre un resguardo: `D` es la misma.

## 4. Reparto de la clave
`K` (32 bytes aleatorios) se reparte con Shamir en `s_1 … s_G` con umbral `need`; cada `s_g` se reparte entre los miembros del grupo con umbral `k`.

Shamir sobre GF(2⁸) con el polinomio x⁸+x⁴+x³+x+1 (0x11B), byte a byte: para cada byte se toma un polinomio de grado `umbral−1` cuyo término constante es el byte del secreto y el resto aleatorio; la participación `x` es su valor en `x` (1…n). Se recupera por interpolación de Lagrange en 0 con exactamente `umbral` participaciones.

Para el miembro `x` del grupo `g` con participación `s`:
```
com = H("QSEL3/share", sid, u32(g), u32(x), s)
(ss, ct) = KEM.Encap(pk_custodio)
wk  = HKDF(ss, lp("QSEL3/wrap") ‖ lp(sid) ‖ lp(u32(g)) ‖ lp(u32(x)) ‖ lp(id) ‖ lp(sender))      (id y sender en bytes, no en hex)
box = AEAD0(wk, s, aad = com)
```

## 5. Candados y cuerpo
Un candado es una clave maestra simétrica de 32 bytes **aleatorios** (NO DEBE derivarse de una frase) con un identificador aleatorio de 16 bytes. Para un archivo:
```
clave_por_archivo = HKDF(maestra, lp("QSEL3/lock-file") ‖ lp(sid))
```
El guardián DEBE cumplir la sección 10 y entregar solo `clave_por_archivo`, nunca la maestra, en una **ficha**: JSON con exactamente `{v: 3, file: hex(D), id: hex, key: base64(clave_por_archivo)}`. La ficha es secreta y NO se cifra con clave pública: se transporta por un canal que no dependa de ella.
El lector DEBE exigir una ficha válida (archivo, identificador y compromiso) por **cada** candado de la cabecera.

`payload_key = HKDF(K ‖ f_1 ‖ … ‖ f_n, lp("QSEL3/payload") ‖ lp(D))`, con `f_i` la clave por archivo del candado `i` en el orden de la cabecera (sin candados, el material es `K`). El claro se parte en trozos de 65 536 bytes; el último puede ser más corto y solo puede estar vacío si el archivo entero lo está. Un claro múltiplo exacto de 65 536 NO lleva un trozo vacío final.
Trozo `i` (desde 0): `AEAD(payload_key, nonce = i en 11 bytes big-endian ‖ f, claro_i, aad vacío)`, con `f = 01` en el último y `00` en los demás. Cada trozo cifrado mide su claro + 16.

## 6. Solicitud de apertura
JSON con exactamente `{v: 4, file: hex(D), kem: base64(pk de apertura), signer: base64(pk de firma), reason, issued, expires, nonce: base64(16 bytes aleatorios), sig: base64}`.
`reason`: 1 a 500 caracteres imprimibles (misma regla que `name`). `issued` y `expires`: segundos Unix, enteros, con `issued < expires ≤ issued + 604800`.
```
mensaje = lp(D) ‖ lp(pk_apertura) ‖ lp(pk_firmante) ‖ lp(UTF-8(reason)) ‖ lp(u64(issued)) ‖ lp(u64(expires)) ‖ lp(nonce)
sig = Firma("QSEL3/request", mensaje)
identificador = SHA-256(mensaje)            (no de los bytes JSON)
```
Quien la atiende (custodio o guardián) DEBE comprobar: archivo íntegro (sección 3), `file = D`, huella del firmante en `openers`, firma válida, `issued − 300 ≤ ahora ≤ expires` con su propio reloj, y mostrar el motivo a la persona.

## 7. Contribución de un custodio
El custodio abre `box` con su KEM (y comprueba `com`), y la re-cifra para la clave de apertura de la solicitud:
```
(ss2, ct2) = KEM.Encap(pk_apertura)
ctx = lp("QSEL3/contrib") ‖ lp(D) ‖ lp(u32(g)) ‖ lp(u32(x)) ‖ lp(SHA-256(pk_apertura))
box2 = AEAD0(HKDF(ss2, ctx), s, aad = ctx)
```
JSON con exactamente `{v: 3, file: hex(D), g, x, ct: base64(ct2), box: base64(box2)}`.

## 8. Apertura
1. Verificar el archivo (sección 3) y reunir las fichas de todos los candados (sección 5).
2. Por cada contribución: comprobar `file`, rango de `g` y `x`, abrir `box2`, comprobar `com` del miembro. Las que fallen se descartan e informan.
3. Por cada grupo con al menos `k` participaciones válidas (sin contar repetidas), recuperar `s_g` con `k` de ellas: DEBE coincidir con el `com` del grupo. Si no coincide, el lector PUEDE probar otros subconjuntos de `k` (el código prueba hasta 256, dejando fuera una, dos… participaciones); si ninguno coincide, ese grupo está mal repartido y no cuenta.
4. Con al menos `need` grupos correctos, recuperar `K` con `need` de ellos (con la misma libertad de probar subconjuntos); DEBE cumplir `commit`. Como solo se acepta lo que cumple los compromisos, dos aperturas nunca obtienen claves distintas.
5. Descifrar; solo publicar la salida si **todos** los trozos y la huella del cuerpo verificada en el paso 1 coinciden.

## 9. Lo que el formato NO da
Revocación de una ficha ya emitida (retirar un archivo o destruir la maestra solo impide emitir nuevas), secreto hacia adelante, protección contra repetición ante los **custodios** (sí ante el guardián), ocultación de metadatos, identificación de la **persona** que aporta una contribución, ni protección frente a quien abre (que obtiene `K`).

## 10. Guardián de un candado
No forma parte del archivo: es el comportamiento que DEBE tener quien guarda una maestra.

**Condiciones de entrega** (todas): (1) sección 6; (2) el archivo exige ese candado y la maestra cumple su `com`; (3) `D` está registrada y no retirada; (4) el solicitante está de alta y no dado de baja; (5) prueba simétrica válida; (6) el `identificador` de la solicitud no se ha atendido. La entrega DEBE anotarse en el diario **antes** de devolver la ficha.

**Registro:** se hace al sellar, tras verificar el archivo y el compromiso. Una huella retirada NO DEBE volver a registrarse. Un solicitante dado de baja NO DEBE volver a darse de alta.

**Secreto y prueba** (`id_candado` y huella del solicitante en bytes):
```
secreto = HKDF(maestra, lp("QSEL3/keeper-requester") ‖ lp(id_candado) ‖ lp(huella_solicitante))
prueba  = HMAC-SHA256(secreto, lp("QSEL3/keeper-proof") ‖ lp(identificador))
```
El secreto se entrega al solicitante por un canal que no dependa de clave pública.

**Diario** (guardián y custodios): una línea por entrada, cada una un JSON canónico `{data, mac, n, type}` terminado en salto de línea; `n` desde 0.
```
k_guardián = HKDF(maestra, lp("QSEL3/keeper-journal") ‖ lp(id_candado))
k_custodio = HKDF(semilla_privada_del_custodio, lp("QSEL3/custodian-journal"))
mac_n = HMAC-SHA256(k, lp("QSEL3/journal-entry") ‖ lp(mac_{n−1}) ‖ lp(canónico({data, n, type})))        mac_{−1} = 32 bytes a cero
```
JSON canónico: claves ordenadas, sin espacios, UTF-8 sin escapes de no ASCII. `data` lleva siempre `at` (segundos Unix) y además, según el tipo: guardián `register {file}`, `withdraw {file}`, `enroll {requester}`, `revoke {requester}`, `deliver {request, file, requester, expires, reason}`; custodio `serve {request, file, requester, expires, reason}`.
El lector DEBE verificar el diario entero antes de cada operación y negarse ante cualquier fallo; las operaciones sobre un diario DEBEN excluirse entre sí; NO DEBE anotarse nada si el reloj está más de 300 s antes del último `at`.
Un custodio con diario DEBE atender cada `identificador` una sola vez y anotar antes de entregar su participación.

**Ancla** (opcional, en otro medio): `{n, mac, tag}` con `tag = HMAC-SHA256(k, lp("QSEL3/journal-anchor") ‖ lp(u64(n)) ‖ lp(mac_{n−1}))`, reescrita tras cada anotación. El diario DEBE contener en la posición `n` la entrada con ese `mac`; un ancla que falta ante un diario con entradas DEBE detener las operaciones hasta que una persona la adopte expresamente. Sin ancla (ni cabeza anotada fuera), cortar el **final** del diario no se detecta.

## 11. Reparto de la maestra de un candado
Shamir (sección 4) de la maestra en `n` partes con umbral `2 ≤ k ≤ n ≤ 16`. Cada parte lleva `id`, etiqueta, `k`, su `x`, los compromisos de todas `H("QSEL3/lock-share", id, u32(x), parte)` y `H("QSEL3/lock-master", id, maestra)`. Al reunirlas DEBEN comprobarse la coherencia entre partes, cada parte y la maestra reconstruida.

## 12. Archivos de clave
JSON canónico `{v: 1, kind, level, algorithm, extra, n, salt, nonce, box}`: `box = ChaCha20-Poly1305(scrypt(frase, salt, n, r=8, p=1), nonce, secreto, aad = canónico(todos los campos menos box))`. `2^14 ≤ n ≤ 2^17`, potencia de dos (el escritor usa `2^15`). Las claves públicas son `{kind, level, algorithm, public}` y el lector DEBE comprobar `kind` y `algorithm`.
