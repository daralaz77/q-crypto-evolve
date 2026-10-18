# Transporte TLS 1.3 con X25519MLKEM768 (opción A)

**Qué es:** la vía recomendada para producción (ADR-3 y ADR-6): TLS 1.3 con el grupo de intercambio híbrido **X25519MLKEM768**, que ya es un protocolo revisado y desplegado, en lugar de QCE1.
**Qué NO es:** no implementa criptografía. Configura y **verifica** la pila TLS del sistema (OpenSSL ≥ 3.5; aquí 3.6.4) para que no pueda negociar nada clásico.
**Código:** `qce/transport/tls13.py` · PKI de laboratorio: `qce/transport/pki.py` · pruebas: `tests/test_tls13_transport.py` (13) y `tests/tls_scenarios.py` · comprobación: `python -m qce tls-check`.

## 1. Garantías y cómo se comprueban

| Garantía | Mecanismo | Prueba |
|---|---|---|
| Solo TLS 1.3 | `minimum_version` en cada contexto + `MinProtocol` en la configuración de OpenSSL | cliente limitado a TLS 1.2 rechazado; `openssl s_client -tls1_2` sin cifrado negociado |
| **Grupo híbrido único** (sin degradación) | `Groups = X25519MLKEM768` en la configuración de OpenSSL | clientes y servidores que solo ofrecen P-256, P-384, X25519 o X448 **no conectan**; `openssl s_client -groups X25519` y `-groups P-256` terminan en `handshake failure` y `Negotiated TLS1.3 group: <NULL>` |
| Confirmación por un tercero | `openssl s_client -groups X25519MLKEM768` | `Negotiated TLS1.3 group: X25519MLKEM768` |
| **Falla cerrado** si la configuración no se aplica | atestación en bucle local antes de crear cualquier contexto | si se importa `cryptography` antes que el módulo, `TransportMisconfigured` (probado) |
| Cadena y nombre del servidor verificados | `PROTOCOL_TLS_CLIENT` + CA explícita (nunca el almacén del sistema) | nombre incorrecto, CA no fiable y certificado caducado: rechazados |
| Autenticación **mutua** (QCE1 no la tiene) | `server_context(..., client_ca=...)` → `CERT_REQUIRED` | sin certificado de cliente el manejador nunca ve la conexión; con él ve la identidad |
| Sin reanudación ni compresión | `num_tickets = 0`, `OP_NO_TICKET`, `OP_NO_COMPRESSION` | propiedades de los contextos |
| Mensajes acotados | longitud de 4 bytes y máximo 1 MiB | mensaje mayor rechazado |
| **Autenticación poscuántica real** | certificado **ML-DSA-65** (OpenSSL) con el mismo transporte | apretón TLS 1.3 completo con `Signature Algorithm: ML-DSA-65` |

## 2. Por qué hay una «atestación» (limitación de Python 3.14)

`ssl` de Python 3.14 **no permite elegir los grupos** (`set_groups` no existe) **ni informa del grupo negociado**. Por eso:

1. Los grupos y los cifrados se fijan en una configuración de OpenSSL (`OPENSSL_CONF`), que el módulo genera con permisos 0600 y exporta **al importarse**.
2. Medido en este equipo: la configuración **solo se aplica si se fija antes de importar `cryptography`** en el proceso. Si no, se ignora en silencio. Eso es justo lo que la atestación detecta: abre conexiones locales con pares limitados a cada grupo clásico y a TLS 1.2, y exige que ninguna conecte (y que el par por defecto sí). Si algo conecta, lanza `TransportMisconfigured` y no se crea ningún canal.
3. Regla de uso: **importar `qce.transport.tls13` lo primero**, o arrancar el servicio con `child_env()`. `python -m qce tls-check` lo hace bien.

Cuando Python ofrezca `set_groups` y la consulta del grupo negociado, la atestación se podrá sustituir por una comprobación directa.

## 3. Qué cambia respecto a QCE1

| Tema | QCE1 | TLS 1.3 híbrido |
|---|---|---|
| Revisión del protocolo | ninguna externa | revisado y desplegado públicamente |
| Autenticación del cliente | no existe (no objetivo) | opcional por certificado (mTLS) |
| Firma poscuántica | ML-DSA-65 + Ed25519 | certificado ML-DSA-65 (probado) o ECDSA clásico |
| Preguntas abiertas 1–10 | abiertas | dejan de aplicar al uso de producción |
| **Mezcla de clave QKD** | sí (concatenación en HKDF; pregunta abierta 1) | **no resuelta aquí** (ver §4) |

## 4. Custodia de la clave privada del servidor (`qce/transport/custody.py`)

La clave **nace dentro del KeyStore** (PKCS#8, propósito `TLS`) y se persiste cifrada con el vault (scrypt + ChaCha20-Poly1305). No existe un archivo `.key` en claro.

| Paso | Qué ocurre | Comprobado |
|---|---|---|
| Provisión | se genera la clave en la custodia y se emite una **CSR**; la CA (aquí, la de laboratorio) solo ve la CSR | flujo `csr_flow` |
| Instalación | solo se acepta un certificado de **esa** clave, vigente y que cubra el nombre | otra clave, otro nombre y caducado: rechazados |
| Uso | `KeyStore.use(..., Purpose.TLS, "sign")` decide si está ACTIVE, vigente y es de propósito TLS | una clave TLS no sirve para cifrar datos; una RETIRED, REVOKED o caducada no crea contextos |
| Cargar en `ssl` | Python solo acepta un archivo: se escribe una copia **cifrada** (contraseña aleatoria solo en memoria, directorio 0700, archivo 0600), se carga y se borra sobrescrita | cabecera `ENCRYPTED PRIVATE KEY`; ningún archivo con `PRIVATE KEY` tras operar; sin directorios temporales sobrantes |
| Rotación | nueva clave + certificado, la anterior pasa a **RETIRED**, `server.set_context(...)` para conexiones nuevas | cambia el número de serie; la conexión abierta antes sigue funcionando |
| Revocación | se borra el secreto y `stop_accepting()` deja de atender conexiones nuevas | sin secreto, sin contexto y las conexiones nuevas fallan |
| Restauración | el vault se recarga (con anti-restauración) y la custodia sirve de nuevo | el servidor funciona con la clave restaurada |
| Auditoría | la cadena de hashes registra crear/activar/retirar/revocar, nunca material de clave | DER/PEM no aparecen en el registro |

**Qué sigue sin garantizar (ver §5):** la clave en claro sí está en la **memoria** del proceso mientras el contexto exista (no hay forma de evitarlo con `ssl`), y el borrado en Python es de mejor esfuerzo. Un HSM o un agente de claves (clave que nunca sale del dispositivo) sigue siendo la solución completa.

## 5. Límites y brechas (declaradas)

- **QKD no se integra en este transporte.** TLS 1.3 admite una clave externa (PSK) para mezclar un secreto como el de QKD, pero la API de PSK de `ssl` en Python 3.14 **solo funciona hasta TLS 1.2** (probado: el apretón TLS 1.3 con PSK falla con `NO_SUITABLE_SIGNATURE_ALGORITHM`). Opciones: una versión futura de Python, otra pila TLS con PSK externo en 1.3, o seguir con QCE1 solo para el modo QKD.
- **La clave privada vive en el KeyStore cifrado (§4), pero no en un HSM:** está en claro en la memoria del proceso mientras exista el contexto; una persona con acceso a esa memoria (volcado, depurador) la obtiene. La CA, la política de caducidad y la rotación automática (hoy se invoca a mano) siguen siendo de laboratorio.
- **Sin revocación de certificados** (CRL/OCSP) ni gestión del ciclo de vida: la PKI incluida es de laboratorio (ECDSA P-256, 1 día).
- **Los certificados ML-DSA-65 de las pruebas los genera el `openssl` del sistema** (3.6.4); la compatibilidad con otras pilas y clientes no se ha probado.
- **Dependencia de OpenSSL ≥ 3.5** y de que el entorno no sustituya `OPENSSL_CONF` por una configuración permisiva; la atestación lo detecta, pero solo en el momento de crear contextos.
- **El servidor de ejemplo (`TlsServer`) es de laboratorio:** hilo por conexión, sin límites de conexiones ni de tasa.
- **Autenticación ECDSA por defecto en laboratorio:** protege contra captura-hoy-descifrado-mañana (el KEM es híbrido), pero una firma clásica podría falsificarse con un ordenador cuántico futuro; para eso está la opción ML-DSA.
- Nada de esto sustituye la **revisión de un experto** de la configuración TLS y de su despliegue.
