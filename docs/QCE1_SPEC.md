# QCE1 — especificación del protocolo de apretón de manos y registros

**Estado:** borrador 0.1 derivado del código (`qce/protocols/session.py`, `qce/pqc/hybrid.py`, `qce/symmetric/aead.py`, `qce/core/encoding.py`).
**Propósito:** que un revisor criptográfico externo, o un modelo formal (Tamarin/ProVerif), pueda trabajar sin leer Python.
**Qué NO es:** no está revisado por terceros, no es un estándar y no sustituye a TLS 1.3 con X25519MLKEM768 (ver `decisions/ADRs.md`, ADR-3).
La especificación se mantiene anclada al código: `tests/test_spec_anchors.py` comprueba las constantes de la tabla de §12 y re-deriva
las claves, los MAC y los registros **desde este texto**, con código independiente, contra una ejecución real del protocolo.

## 1. Objetivos y no objetivos

| Objetivo (a verificar) | Cómo se pretende lograr |
|---|---|
| G1. Autenticación del servidor | Firma híbrida AND (Ed25519 + ML-DSA-65) sobre el transcript, con identidad fijada (pinning) |
| G2. Confidencialidad de la sesión frente a un atacante clásico **o** cuántico | KEM híbrido X25519 + ML-KEM-768 combinado con HKDF |
| G3. Secreto hacia adelante | KEM efímero por sesión, descartado tras usarse |
| G4. Anti-degradación | Dos vías independientes: la firma cubre el ClientHello (aguanta aunque caigan los dos KEM) y el MAC de confirmación cubre todo el transcript (mientras algún KEM resista); el servidor solo elige entre lo ofrecido y permitido |
| G5. Confirmación de clave mutua | MAC sobre el transcript con una clave derivada |
| G6. Integridad, anti-repetición y no reflexión en los registros | AEAD con contador, ventana deslizante y dirección en el AAD |
| G7. (opcional) Mezcla de una clave QKD sin sustituir al secreto poscuántico | Se concatena al material de entrada de HKDF; falla cerrado si falta |

**No objetivos (declarados):** autenticación del **cliente** (no existe); ocultar la identidad del servidor o las suites; protección frente a
canales laterales; resistencia a denegación de servicio; renegociación o reanudación de sesión (no existen; cada sesión es un apretón nuevo);
0-RTT; rotación de claves dentro de una sesión (al llegar al límite de registros hay que renegociar).

## 2. Modelo de atacante y supuestos

- Atacante de red activo (Dolev-Yao): lee, descarta, repite, reordena, inyecta y modifica mensajes entre las partes, y puede iniciar sesiones propias con el servidor.
- Puede comprometer **uno** de los dos componentes de cada híbrido (p. ej. romper X25519 con un ordenador cuántico, o hallar un fallo en ML-KEM). G2 y G1 deben mantenerse con el otro componente.
- Puede comprometer la identidad a largo plazo del servidor **después** de la sesión: G3 debe mantenerse.
- El cliente conoce de antemano la clave pública de identidad del servidor (`server_identity_pk`) por un canal fiable. **Cómo llega es un supuesto externo.**
- Se asume que las primitivas son seguras según sus estándares: ML-KEM-768 (FIPS 203), ML-DSA-65 (FIPS 204), X25519 (RFC 7748), Ed25519 (RFC 8032), HKDF-SHA256 (RFC 5869), HMAC-SHA256, SHA-256, ChaCha20-Poly1305 (RFC 8439), AES-256-GCM.
- El generador de números aleatorios del sistema operativo (`os.urandom`) es bueno.

## 3. Notación

- `a ‖ b`: concatenación. `u8`, `u32`, `u64`: enteros sin signo en big-endian.
- `len4(x) = u32(|x|) ‖ x`.
- `H(x1, …, xn) = SHA256( len4(x1) ‖ … ‖ len4(xn) )` — hash con prefijos de longitud (transcript hash).
- `fp(pk) = SHA256(pk)` — huella de una clave pública de identidad.
- `HKDF(ikm, info, L, salt)` = HKDF-SHA256 (extract+expand), salida de `L` bytes.
- `MAC(k, m) = HMAC-SHA256(k, m)`.

## 4. Primitivas compuestas

### 4.1 KEM híbrido `X25519+ML-KEM-768`
- Clave pública `pk = X_pk(32) ‖ M_pk(1184)` → 1216 bytes. Texto cifrado `ct = X_eph_pk(32) ‖ M_ct(1088)` → 1120 bytes.
- `Encaps(pk)`: genera `eph` X25519; `ss_x = X25519(eph, X_pk)`; `(ss_m, M_ct) = ML-KEM-768.Encaps(M_pk)`; `ct = eph_pk ‖ M_ct`;
  `K = HKDF(ikm = ss_m ‖ ss_x, info = LABEL_KEM ‖ ct ‖ pk, L = 32, salt = ninguna)`. Devuelve `(K, ct)`.
- `Decaps(sk, ct)`: simétrico. Un punto X25519 de orden pequeño (secreto compartido nulo) se rechaza; ML-KEM aplica rechazo implícito (FIPS 203).
- `LABEL_KEM = "QCE1/hybrid-kem/X25519+ML-KEM-768"`.

**Nivel ALTO (opcional).** El mismo KEM con ML-KEM-1024 en lugar de ML-KEM-768: `pk = X_pk(32) ‖ M_pk(1568)` → 1600 bytes; `ct = X_eph_pk(32) ‖ M_ct(1568)` → 1600 bytes; `LABEL_KEM_HIGH = "QCE1/hybrid-kem/X25519+ML-KEM-1024"`. La etiqueta distinta separa dominios: un secreto de un nivel nunca coincide con el del otro. El nivel **no se deduce de las longitudes recibidas**: lo fija la suite negociada (que va firmada en el transcript) y cada operación comprueba las longitudes contra el nivel esperado.

### 4.2 Firma híbrida `Ed25519+ML-DSA-65`
- Clave pública `pk = Ed_pk(32) ‖ ML_pk(1952)` → 1984 bytes. Firma `sig = Ed_sig(64) ‖ ML_sig(3309)` → 3373 bytes.
- `Sign(sk, msg, ctx)`: `Ed_sig = Ed25519(msg' )` con `msg' = ctx ‖ 0x00 ‖ msg`; `ML_sig = ML-DSA-65.Sign(msg, ctx)` (contexto nativo de FIPS 204).
- `Verify`: **ambas** deben ser válidas; cualquier otra longitud de clave o firma se rechaza.

**Nivel ALTO (opcional).** La misma firma con ML-DSA-87: `pk = Ed_pk(32) ‖ ML_pk(2592)` → 2624 bytes; `sig = Ed_sig(64) ‖ ML_sig(4627)` → 4691 bytes. La identidad del servidor debe ser del nivel de la suite elegida; si no, el servidor aborta (no firma con otro nivel).

## 5. Codificación en el cable

Mensaje = `tag(u8) ‖ n(u8) ‖ campo_1 ‖ … ‖ campo_n`, con `campo_i = len4(dato_i)`. El receptor exige: tag exacto, `n` exacto, cada longitud ≤ 16384
(`MAX_FIELD`), nada fuera de rango y **ningún byte sobrante**. A lo sumo 16 campos.

| Mensaje | tag | Campos |
|---|---|---|
| ClientHello (`m1`) | 0x01 | `version`, `nonce_c`(32), `suites`, `qkd_id` |
| ServerHello (`m2`) | 0x02 | `suite`, `nonce_s`(32), `kem_pk`(1216), `sig`(3373) |
| ClientFinish (`m3`) | 0x03 | `kem_ct`(1120), `mac_c`(32) |
| ServerFinish (`m4`) | 0x04 | `mac_s`(32) |
| Registro | 0x10 | `seq`(8, u64), `ciphertext` |

`version = "QCE1"`. `suites` = identificadores ASCII separados por coma (máximo 8). `qkd_id` vacío = sin QKD.

## 6. Apretón de manos

```
Cliente (conoce server_identity_pk)                         Servidor (identidad id_sk, id_pk)
m1 = ClientHello(QCE1, nonce_c, suites, qkd_id)  ───────▶
                                                           elige suite = primera de la política que esté en `suites`
                                                           si qkd_id ≠ ∅ y no hay clave QKD → ABORTA
                                                           (kem_sk, kem_pk) = KEM.Gen()          [efímera]
                                                           signed = H(m1, suite, nonce_s, kem_pk, fp(id_pk))
                                                           sig = Sign(id_sk, signed, "QCE1/server-hello")
                                       ◀───────  m2 = ServerHello(suite, nonce_s, kem_pk, sig)
verifica suite ∈ ofrecidas y permitida
signed = H(m1, suite, nonce_s, kem_pk, fp(server_identity_pk))
Verify(server_identity_pk, signed, sig)
(ss, ct) = Encaps(kem_pk)
th = H(m1, m2, ct)
secret = ss ‖ qkd_key                       (qkd_key vacía si no hay QKD)
keys = HKDF(secret, "QCE1/keys" ‖ th, 104, salt = th)
mac_c = MAC(ck, "client" ‖ th)
m3 = ClientFinish(ct, mac_c)  ───────▶
                                                           ss = Decaps(kem_sk, ct); kem_sk se descarta (siempre)
                                                           th = H(m1, m2, ct); mismas claves
                                                           comprueba mac_c en tiempo constante
                                       ◀───────  m4 = ServerFinish( MAC(ck, "server" ‖ th ‖ mac_c) )
comprueba mac_s
```

- El cliente solo acepta `m2` en el estado «ClientHello enviado»; el servidor solo `m3` en «ServerHello enviado». Cualquier otro orden aborta.
- El servidor admite **un único intento** de `m3`: tras el primer fallo el apretón queda cerrado y la clave efímera destruida.
- Elección de suite: `select(offered)` recorre `Policy.allowed_suites` en orden de preferencia del servidor y devuelve la primera presente en `offered`; sin coincidencia aborta.

## 7. Derivación de claves

`keys = HKDF(secret, info = "QCE1/keys" ‖ th, L = 104, salt = th)`, con `th = H(m1, m2, ct)` y `secret = ss ‖ qkd_key`:

| Bytes | Uso |
|---|---|
| `keys[0:32]` | clave cliente→servidor (`k_c2s`) |
| `keys[32:64]` | clave servidor→cliente (`k_s2c`) |
| `keys[64:96]` | clave de confirmación `ck` |
| `keys[96:100]` | prefijo de nonce cliente→servidor |
| `keys[100:104]` | prefijo de nonce servidor→cliente |

`session_id = th[0:16]`.

## 8. Capa de registros

- Cada sentido usa su clave y su prefijo de nonce. `nonce(12) = prefijo(4) ‖ u64(seq)`; `seq` empieza en 0 y solo crece.
- `AAD = session_id ‖ dirección ‖ aad_usuario`, con `dirección = "c"` (cliente→servidor) o `"s"` (servidor→cliente).
- Cifrado: ChaCha20-Poly1305 o AES-256-GCM según la suite elegida.
- Receptor: mantiene una ventana deslizante de 64; rechaza `seq` negativo, repetido o más antiguo que `máximo − 64`; **solo registra** un `seq` tras autenticar.
- Límite: tras 2³² registros por clave el emisor se niega (hay que renegociar).

## 9. Suites

| Id | KEM | Firma | AEAD |
|---|---|---|---|
| `QCE1-XMLKEM768-CHACHA` | X25519+ML-KEM-768 | Ed25519+ML-DSA-65 | ChaCha20-Poly1305 |
| `QCE1-XMLKEM768-AESGCM` | X25519+ML-KEM-768 | Ed25519+ML-DSA-65 | AES-256-GCM |
| `QCE1-XMLKEM1024-AESGCM` | X25519+ML-KEM-1024 | Ed25519+ML-DSA-87 | AES-256-GCM |

La suite de nivel alto está en el registro pero **no en la política por defecto**: se activa a propósito (`Policy(allowed_suites=("QCE1-XMLKEM1024-AESGCM",))`). Usar los parámetros que pide CNSA 2.0 **no hace conforme** al sistema con CNSA 2.0 (el híbrido sigue llevando X25519/Ed25519 y hay más requisitos; ver `docs/FIPS_140_3.md`).

La política rechaza cualquier suite no listada o sin componente poscuántico. `QCE0-X25519-CHACHA` figura en el registro como `forbidden`.

## 10. Clave QKD opcional

Si el cliente anuncia `qkd_id`, el servidor busca la clave por ese id; si no la tiene, **aborta** (no hay sesión sin QKD). Ambos añaden `qkd_key` a `secret`.
`qkd_key` no entra en el transcript (solo su id); una clave distinta en cada extremo hace fallar la confirmación `mac_c`.

## 11. Propiedades que se pretende demostrar (para el modelo formal)

1. **Acuerdo inyectivo del servidor:** si el cliente termina con `server_identity_pk` y transcript `th`, el servidor con esa identidad participó con el mismo `th` y no hay otra sesión de cliente con el mismo `th`.
2. **Secreto** de `k_c2s`, `k_s2c` frente a un atacante que controla la red.
3. **Secreto hacia adelante:** comprometer `id_sk` después de terminar no revela las claves de sesión.
4. **Anti-degradación:** el atacante no puede hacer que ambos acepten una suite distinta de la que ambos aceptarían sin él.
5. **Propiedad híbrida:** 1–4 siguen valiendo si el atacante rompe X25519 **o** rompe ML-KEM (y, para la firma, Ed25519 **o** ML-DSA).
6. **No reflexión** de registros y **anti-repetición** dentro de una sesión.

## 12. Constantes ancladas al código

Este bloque lo lee `tests/test_spec_anchors.py` y lo compara con el código. Si cambias el código, cambia aquí y revisa el resto del documento.

```constants
VERSION = QCE1
TAG_CLIENT_HELLO = 1
TAG_SERVER_HELLO = 2
TAG_CLIENT_FINISH = 3
TAG_SERVER_FINISH = 4
TAG_RECORD = 16
SIGN_CONTEXT = QCE1/server-hello
KEM_LABEL = QCE1/hybrid-kem/X25519+ML-KEM-768
KEM_PK_LEN = 1216
KEM_CT_LEN = 1120
SIG_PK_LEN = 1984
SIG_LEN = 3373
KEM_LABEL_HIGH = QCE1/hybrid-kem/X25519+ML-KEM-1024
KEM_PK_LEN_HIGH = 1600
KEM_CT_LEN_HIGH = 1600
SIG_PK_LEN_HIGH = 2624
SIG_LEN_HIGH = 4691
KEYS_INFO_PREFIX = QCE1/keys
KEYS_LEN = 104
SESSION_ID_LEN = 16
MAX_FIELD = 16384
MAX_FIELDS = 16
REPLAY_WINDOW = 64
```

## 13. Preguntas abiertas para el revisor

Puntos que el autor considera discutibles y que se quieren ver cuestionados, no defendidos:

1. **Mezcla de la clave QKD por concatenación** (`secret = ss ‖ qkd_key`): ¿basta con HKDF sobre la concatenación, o hace falta un combinador con separación de dominios por componente? La clave QKD no entra en el transcript.
2. **`salt = th` y `th` también en `info`:** ¿es redundante o inofensivo? ¿Debería usarse una etiqueta de extracción distinta por dirección?
3. **Una sola salida HKDF dividida en 5 trozos** (claves, confirmación y prefijos): ¿conviene extraer y expandir por separado con etiquetas explícitas?
4. **(Parcialmente contestada por el modelo formal, ver `docs/QCE1_FORMAL.md` §3.3 y §3.5.) El MAC de confirmación del cliente cubre `th`, pero la firma del servidor no cubre `ct`:** ¿el orden «firma sobre m1 y m2-parcial, confirmación sobre todo» deja algún ataque de tipo unknown-key-share o de re-encapsulación? (La huella de la identidad va dentro de lo firmado.)
5. **Ausencia de autenticación del cliente:** ¿está bien documentado y aceptable para el caso de uso?
6. **`session_id` de 128 bits** truncado del transcript y **`dirección` en el AAD** además de claves distintas por sentido: ¿redundancia útil o confusión?
7. **Nonce por contador con prefijo derivado de 4 bytes:** ¿alguna interacción con AES-GCM al renegociar con el mismo prefijo? (Cada sesión tiene claves nuevas, pero conviene confirmarlo.)
8. **Formato de `suites` como texto separado por comas:** ¿riesgo de ambigüedad o inyección más allá de las validaciones actuales (máx. 8, ASCII, lista blanca)?
9. **Ventana de repetición solo en memoria:** sin persistencia entre reinicios; la renegociación obligatoria lo cubre, ¿es suficiente?
10. **Un único intento de `m3`:** ¿facilita denegación de servicio a un atacante en la ruta? (Ya puede descartar mensajes.)

## 14. Cómo se comprueba que esta especificación es fiel al código

- `tests/test_spec_anchors.py::test_constants_table_matches_code` — la tabla de §12 frente a las constantes reales.
- `tests/test_spec_anchors.py::test_independent_rederivation_matches_a_real_handshake` — ejecuta un apretón real y, **solo con las fórmulas de este documento**, recalcula `th`, las claves, los dos MAC, verifica la firma del servidor y descifra un registro con ChaCha20-Poly1305 directo.
- `tests/test_spec_anchors.py::test_independent_rederivation_with_qkd_and_aesgcm` — lo mismo con QKD y AES-256-GCM.
- Lo que **no** comprueba: que el modelo formal futuro sea correcto, ni propiedades de seguridad (para eso son el modelo y la revisión externa).

## 15. Verificación formal

El diseño se modeló en Tamarin Prover: `formal/qce1.spthy`; resultados, lecturas y límites en `docs/QCE1_FORMAL.md`. Resumen: la propiedad híbrida (§11, punto 5)
se verifica para cualquier combinación de un KEM y una firma que resistan; si caen ambos KEM o ambas firmas, las propiedades se pierden, como era de esperar.
La clave QKD, además de mezclar secreto, autentica implícitamente al cliente (observación del modelo, no un objetivo previo).

## 16. Conformidad modelo-código

`docs/QCE1_CONFORMANCE.md`: trazas del código real (con un atacante de red activo) se convierten en eventos del modelo y se comprueban sus lemas y sus guardas; el código reproduce las falsificaciones esperadas del modelo con roturas.

