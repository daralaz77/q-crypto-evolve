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

## 3b. Segunda implementación independiente: GnuTLS (2026-10-19)
`tests/test_tls13_psk_gnutls.py` prueba la PSK externa contra **GnuTLS 3.8.13** (`gnutls-cli`, `gnutls-serv`), código distinto del de OpenSSL, en los dos sentidos: un cliente GnuTLS completa el apretón con nuestro servidor e intercambia datos;
nuestro cliente completa el apretón con `gnutls-serv`; con una clave o una identidad equivocadas GnuTLS y nuestro servidor rechazan y la clave del servidor no se gasta.
Esto contrasta con una implementación ajena la identidad, la derivación de la PSK, el binder y el calendario de claves en modo `psk_dhe_ke`.
**Límite:** el GnuTLS de Homebrew no incluye X25519MLKEM768 (solo grupos clásicos), así que estas pruebas usan el parámetro `group="X25519"`, que existe **solo para interoperar** (lista cerrada `GROUPS`; el valor por defecto sigue siendo el híbrido, y
la atestación exige el grupo pedido). Con `X25519` no hay protección frente a un ordenador cuántico. El grupo híbrido se contrasta con otra implementación en §3c (Mozilla NSS). Una prueba comprueba además que **un cliente con el valor por defecto no baja en silencio a X25519**
cuando el servidor no ofrece el híbrido (falla cerrado). Y la suite exige AES-128-GCM-SHA256 en estas pruebas porque la PSK externa de GnuTLS va ligada a SHA-256.

## 3c. Segunda implementación del HÍBRIDO: Mozilla NSS (2026-10-20)
NSS 3.125 (`tstclnt`, `selfserv`, `certutil`; código distinto de OpenSSL y de GnuTLS) **sí trae X25519MLKEM768** y acepta PSK externa, así que contrasta lo que GnuTLS no podía. `tests/test_interop_nss.py` (11 pruebas) y el escenario `nss` de `tests/test_hsm_tls.py` comprueban:
- **Híbrido + PSK externa:** un cliente NSS completa el apretón con nuestro servidor con grupo `X25519MLKEM768`, TLS 1.3 y la PSK derivada de la clave QKD; lo atestigua nuestro servidor (identidad, grupo, suite, versión), NSS recibe la respuesta cifrada y la clave se consume.
- **La derivación queda fijada:** la PSK que recibe NSS se calcula en la prueba con HKDF-SHA256 directo, no con `prepare_psk`; se comprobó que cambiar la etiqueta de dominio hace fallar la prueba (con `prepare_psk` en los dos lados no habría detectado nada).
- **PSK o identidad equivocadas:** NSS y nuestro servidor rechazan y la clave del servidor no se gasta.
- **Sin bajada silenciosa:** un NSS que solo ofrece X25519 no completa el apretón con nuestro servidor híbrido, y nuestro cliente con certificados se niega a usar un servidor NSS que solo ofrece X25519.
- **Híbrido con certificados:** nuestro cliente TLS completa TLS 1.3 con un `selfserv` que solo ofrece `x25519mlkem768`.
- **Servidor con la clave en el HSM:** NSS verifica la cadena y la firma hecha por el token (SoftHSM) y negocia el híbrido; sin confiar en la CA, NSS rechaza el certificado (`unknown ca`), es decir, de verdad lo verifica.

- **Nuestro cliente PSK contra un servidor NSS:** `selfserv` NO sirve (no aplica la PSK externa en el servidor: autentica por certificado aunque se le dé una PSK, incluso frente a `tstclnt`; se probó con la configuración por defecto, solo la suite AES-128 y un cliente que no puede usar el certificado, y en los tres casos no usó la PSK). Por eso hay un servidor mínimo sobre la propia biblioteca NSS, `tests/helpers/nss_psk_server.c` (~100 líneas, se compila al vuelo con `cc`), que añade la PSK al socket aceptado. Resultado: nuestro cliente completa TLS 1.3 con `X25519MLKEM768` y AES-128-GCM-SHA256, y **NSS informa que autenticó por PSK** (`ssl_auth_psk`), no por certificado; con clave o identidad equivocadas NSS rechaza; y un NSS que solo ofrece X25519 no consigue que nuestro cliente por defecto baje de grupo.

**Límites medidos:**
- El servidor de prueba necesita un certificado configurado (NSS no ofrece suites TLS 1.3 sin él); lo que se comprueba es que NSS **elige la PSK**, no el certificado. Es un ayudante de prueba escrito por nosotros sobre la biblioteca de NSS: la implementación independiente es NSS, no el ayudante.
- La PSK externa de NSS va ligada a SHA-256, como la de OpenSSL y GnuTLS: con nuestra suite por defecto (AES-256-GCM-SHA384) NSS no completa el apretón y la clave no se gasta (se prueba). La interoperabilidad con NSS exige `TLS_AES_128_GCM_SHA256`.
- Python 3.14 no expone el grupo negociado por conexión en el cliente con certificados: en esa prueba el híbrido se deduce de que NSS solo ofrecía ese grupo y nuestro contexto solo lo acepta. En el cliente PSK sí se atestigua el grupo.
- Las pruebas se saltan solas sin NSS, sin compilador o sin cabeceras de NSS (en Linux las herramientas `tstclnt`/`selfserv` normalmente no vienen empaquetadas). Probado solo en macOS con Homebrew.

## 3d. Grupo híbrido de nivel alto: `SecP384r1MLKEM1024` (2026-10-22)
Además de `X25519MLKEM768` (por defecto) y `X25519` (solo para interoperar), el puente admite `SecP384r1MLKEM1024` (P-384 + ML-KEM-1024, los parámetros poscuánticos de CNSA 2.0) **si se pide** (`group="SecP384r1MLKEM1024"` en los dos lados). No se admite ML-KEM «puro» (`MLKEM1024`, `MLKEM768`) por no llevar componente clásico, ni `SecP256r1MLKEM768`. Un cliente con el grupo por defecto no puede hablar con un servidor de nivel alto (falla, no cambia el nivel en silencio). Se atestigua el grupo negociado en las dos puntas. **Interoperabilidad con NSS** (`secp384r1mlkem1024` en `tstclnt`, y el ayudante en C con el grupo 4589): en los dos sentidos. Límite: la ruta con certificados (`tls13.py`) sigue ofreciendo solo `X25519MLKEM768`.

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
