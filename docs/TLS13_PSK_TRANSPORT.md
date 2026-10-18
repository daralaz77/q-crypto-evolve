# TLS 1.3 con PSK externa (clave QKD) y X25519MLKEM768 — transporte estándar

**Código:** `qce/transport/tls13_psk.py` · **Pruebas:** `tests/test_tls13_psk.py` · **Estado: puente `ctypes` NO REVISADO por terceros; el protocolo es TLS 1.3 de OpenSSL (RFC 8446), no una composición nuestra.**
Es la **opción A** de `docs/QKD_TLS_OPTIONS.md`: la clave QKD entra en el calendario de claves de TLS 1.3 como PSK externa (modo `psk_dhe_ke`: PSK **más** intercambio híbrido), sin protocolo propio por encima.
Sustituye a la capa QIL1 (`docs/QKD_LAYER_SPEC.md`) allí donde haya un OpenSSL ≥ 3.5 utilizable; QIL1 queda como alternativa para pilas sin PSK externa.

## 1. Cómo funciona
1. El cliente y el servidor comparten una clave QKD de un solo uso con identificador `kid` (el `KeyBroker` o un almacén de un solo uso).
2. Ambos derivan la PSK: `psk = HKDF-SHA256(K, salt = ninguna, info = "QCE/TLS13-PSK/1" ‖ lp(kid))`, 32 bytes. (`lp(x)` = longitud de 4 bytes ‖ `x`.) Es preparación de clave, no un protocolo: separa dominios y reduce una clave QKD de longitud arbitraria al tamaño que admite OpenSSL.
3. Se hace un apretón TLS 1.3 de OpenSSL con **solo** el grupo `X25519MLKEM768`, una suite (`TLS_AES_256_GCM_SHA384` por defecto), sin tickets, sin certificados. `kid` viaja como identidad de la PSK (**en claro en el ClientHello**: es propio de TLS 1.3).
4. Autenticación: por posesión de la PSK, en ambos sentidos (binder del cliente, Finished del servidor). No hay certificados ni clave privada de larga duración en esta ruta.
5. Después del apretón el puente **atestigua** lo negociado (versión TLSv1.3, grupo, suite, PSK usada); si algo difiere, cierra y falla.

## 2. Reserva de la clave (servidor)
Al ver el `kid` el servidor **reserva** la clave en su fuente (`reserve`); la **consume** (`commit`) solo si el apretón termina; la **libera** (`release`) si falla, caduca o la atestación no cumple. Un tercero que conozca el `kid` no puede gastarla, y una clave completada no vuelve a usarse. Una clave fuera de rango (<32 o >1024 bytes) se descarta.

## 3. Qué se prueba (y qué no)
- Apretón real: TLSv1.3, `X25519MLKEM768`, `TLS_AES_256_GCM_SHA384`; eco de mensajes con longitud.
- **Interoperabilidad con un cliente de terceros:** `openssl s_client -psk` (OpenSSL de línea de órdenes) completa el apretón con nuestro servidor usando la PSK derivada, y con una PSK mala es rechazado. (La PSK externa de esa herramienta va ligada a SHA-256, por eso la prueba usa `TLS_AES_128_GCM_SHA256` en ese caso; el valor por defecto del producto es AES-256-GCM.)
- Clave equivocada, identificador desconocido, reutilización, gasto por un tercero, reserva exclusiva bajo concurrencia, cliente en silencio (plazo), límites de tamaño y de mensajes, atestación negativa de cada propiedad, clientes concurrentes.
- Falla cerrado sin OpenSSL ≥ 3.5; solo las dos suites permitidas.
- Hallazgo real del trabajo: la cola de errores de OpenSSL es **por hilo**; el cierre fallido de una conexión contaminaba la lectura de otra en el mismo hilo. Corregido y fijado por una prueba.
- **No** se prueba: la corrección de OpenSSL ni de TLS 1.3 (el análisis formal público de TLS 1.3 incluye PSK, pero **no** lo hemos reproducido aquí), la seguridad de memoria del puente `ctypes`, ni ataques de canal lateral.

## 4. Límites
- **El puente `ctypes` es código nuestro y delicado** (tipos C, tiempos de vida de los callbacks, propiedad de `SSL_SESSION`). Una revisión humana debería mirarlo antes de producción.
- El `kid` es visible para un observador de red; no es secreto. La PSK sí lo es.
- Sin secreto hacia adelante respecto de la PSK **por sí sola**; sí lo hay respecto del KEM efímero (modo `psk_dhe_ke`).
- Dependencia de la ruta de `libssl` (`QCE_LIBSSL`, Homebrew, rutas de Linux); no se ha probado en Linux ni en Windows.
- La clave QKD sigue siendo **simulada** (`os.urandom`).
- El material de la PSK permanece en la memoria del proceso mientras OpenSSL la usa (se borra la copia propia en el mejor esfuerzo).

## 5. Rotación y revocación de la ruta con certificados (`TlsKeyCustody`)
- `rotate_if_due(...)`: rota cuando a la clave activa le queda menos de `renew_before_s` (inclusive), también si ya caducó o no hay ninguna; entrega el contexto nuevo al servidor.
- `revoked_certificates()` + `pki.issue_crl(...)` + `tls13.client_context(ca, crl_file=...)`: el cliente comprueba la CRL y **falla cerrado** si la lista falta, es de otra CA o caducó. Sin pasar `crl_file` no se comprueba (límite declarado). No hay OCSP ni distribución automática de la CRL.
- **HSM / agente de claves: no se ha hecho.** Python `ssl` exige la clave privada en el proceso; un HSM necesitaría un proveedor PKCS#11 de OpenSSL que aquí no está. En la ruta PSK no existe clave privada de larga duración, que es la mitigación práctica.
