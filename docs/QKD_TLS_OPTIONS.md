# Cómo integrar QKD con TLS 1.3: tres opciones, verificadas aquí (2026-10-17)

Entorno de las pruebas: macOS arm64, Python 3.14.7 (`ssl` sobre OpenSSL 3.6.4), `openssl` 3.6.4, `cryptography` 50.0.2.
Lo que se mide es **viabilidad técnica en este equipo**, no la seguridad física de ningún equipo QKD (no hay hardware; la clave QKD es simulada).

## Resumen

| | Opción | ¿Estándar? | ¿Funciona aquí desde Python? | Qué aporta |
|---|---|---|---|---|
| **A** | **PSK externo de TLS 1.3** (la clave QKD entra en el calendario de claves de TLS, junto al intercambio híbrido) | Sí (RFC 8446; importación de PSK, RFC 9258) | **No con `ssl` de Python 3.14**; **sí con el `openssl` del sistema** | Seguridad del secreto si resiste el PSK **o** el KEM híbrido; autentica por PSK |
| **B** | **Capa interna con clave QKD, ligada a la sesión TLS** (HKDF con el *channel binding* + MAC de confirmación + AEAD) | No (construcción propia, pequeña) | **Sí**, en Python puro | Autentica al cliente con la clave QKD; sobrevive a un certificado TLS falso; cascada de dos cifrados independientes |
| **C** | **QCE1** con la clave QKD mezclada (lo que ya existe) | No (sin revisión pública) | Sí | Mezcla en el calendario de claves; modelo formal y conformidad hechos |
| — | IKEv2 con PPK (RFC 8784) o WireGuard con PSK | Sí | **No verificable**: no hay `strongswan`/`wg` ni privilegios aquí | Los dos caminos industriales para inyectar claves externas a nivel de red |

## Opción A — PSK externo de TLS 1.3 (verificada con `openssl`, no con Python)

Con `openssl s_server -tls1_3 -nocert -psk <32 bytes> -psk_identity qkd-id-1 -groups X25519MLKEM768 …` y el cliente equivalente:

| Prueba | Resultado |
|---|---|
| PSK correcta + grupo híbrido | `Negotiated TLS1.3 group: X25519MLKEM768`, `Reused, TLSv1.3, Cipher is TLS_AES_128_GCM_SHA256`, **sin certificado** (la autenticación es el PSK) |
| PSK incorrecta | el servidor registra `binder does not verify` y el cliente recibe `decrypt error` |
| PSK correcta pero cliente solo X25519 | `handshake failure`: falla cerrado |
| Desde Python 3.14 (`ssl.set_psk_*_callback`) | `NO_SUITABLE_SIGNATURE_ALGORITHM`: la API de PSK de `ssl` **solo cubre TLS ≤ 1.2** |

Matices: el PSK externo queda asociado a `TLS_AES_128_GCM_SHA256`, que la configuración actual del transporte excluye (`Ciphersuites`); y el `openssl s_server` admite **un** PSK fijo, no una búsqueda por identidad contra el broker. Para usarla desde Python habría que usar un proceso TLS externo (un proceso por conexión o un terminador propio), `ctypes` sobre `libssl` (frágil) o esperar a que `ssl` exponga PSK en 1.3.

## Opción B — capa interna ligada a la sesión (verificada, en Python puro)

Experimento: `docs/experimentos/qkd_inner_layer_poc.py` (no es código de producto ni está cubierto por las puertas).
Tras el apretón TLS 1.3 híbrido, dentro del canal: el cliente envía el id de la clave QKD; ambos derivan `HKDF(clave_QKD, sal = get_channel_binding("tls-unique"))`, se confirman con un MAC y cifran los datos con una segunda capa AEAD.

| Prueba | Resultado medido |
|---|---|
| Intercambio honesto | funciona; **+0,9 ms** frente a 1,0 ms del apretón TLS |
| Clave QKD equivocada | el servidor la rechaza (`no demostró conocer la clave QKD ligada a esta sesión`) |
| Mismo id de clave usado dos veces | el segundo intento se rechaza (consumo único) |
| **Atacante en medio con un certificado falso que el cliente acepta** | el cliente rechaza al atacante y el servidor real rechaza lo retransmitido: **la clave QKD protege aunque falle la autenticación de TLS** |

Puntos a vigilar (por eso no es «solo implementar»):
- `tls-unique` **no está definido para TLS 1.3** (el estándar es `tls-exporter`, RFC 9266, que Python 3.14 no expone). Aquí devuelve el valor de `Finished` (48 bytes) y funciona, pero es un comportamiento de OpenSSL/Python no garantizado.
- La clave QKD **no entra en el calendario de claves de TLS**: la confidencialidad es una cascada de dos cifrados independientes. Es defensa en profundidad razonable, pero **sin prueba formal** hasta modelarla.
- Es una construcción propia: requiere el mismo tratamiento que QCE1 (especificación, modelo y revisión).

## Opción C — QCE1 con QKD (ya existente)

Mezcla la clave en el calendario de claves y tiene modelo formal (la clave QKD autentica implícitamente al cliente y mantiene el secreto con ambos KEM rotos) y conformidad con el código. Pero **no está revisado por terceros** y su pregunta abierta 1 (mezcla por concatenación) sigue sin respuesta.

## Recomendación

**B ahora, A como objetivo, C solo como banco de pruebas.**
1. **B es la única que funciona hoy desde Python**, añade valor real (autenticación del cliente por QKD y resistencia a un certificado comprometido) y su coste es pequeño. Se implementaría con la especificación y el modelo formal de la capa, y se declararía como **no revisada**.
2. **A es la correcta a largo plazo** (estándar, la clave entra en el calendario de claves): cambiar a ella en cuanto una pila TLS accesible desde Python soporte PSK externo en 1.3, o si se acepta un proceso TLS aparte.
3. **C** no debe usarse en producción mientras no haya revisión externa.

Lo que **no** se ha comprobado: la seguridad física de QKD, el comportamiento con un equipo QKD real (ETSI GS QKD 014), IKEv2/WireGuard, ni el rendimiento bajo carga.
