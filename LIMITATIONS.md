# Limitaciones y lo que NO se ha demostrado

Este documento es parte del producto. Un resultado "verde" solo significa lo que la prueba comprueba.

## Estado real (Q-Crypto Evolve, revisado 2026-10-22)
- **Laboratorio.** No hay despliegue, no hay claves de producción, no hay auditoría externa.
- **Estado máximo alcanzable por el sistema:** `VERIFIED`. `RELEASE_APPROVED` exige firma humana (GATE 6) y no se simula.

## Criptografía
- Primitivas: ML-KEM-768 (FIPS 203), ML-DSA-65 (FIPS 204), X25519, Ed25519, ChaCha20-Poly1305 / AES-256-GCM de
  `cryptography` 50.0.2 (OpenSSL 4.0.3 embebido). No se implementó ninguna primitiva propia.
- **SLH-DSA** (SLH-DSA-SHA2-128s) no lo expone `cryptography`: va por un puente `ctypes` al `libcrypto` del sistema (`docs/SLHDSA.md`), sin revisión humana y fuera del apretón (ver más abajo).
- **Dos niveles de parámetros** (`docs/QCE1_SPEC.md` §4, ADR-15): STANDARD (ML-KEM-768 / ML-DSA-65, por defecto) y HIGH (ML-KEM-1024 / ML-DSA-87, opcional: suite `QCE1-XMLKEM1024-AESGCM` fuera de la política por defecto, y el grupo TLS `SecP384r1MLKEM1024` en la ruta PSK). Pasan los vectores ACVP de keyGen (25+25) y sigVer (15, 12 negativos) de 1024/87; siguen sin existir vectores de encapsulación. **HIGH no hace al sistema conforme con CNSA 2.0** (el híbrido lleva X25519/Ed25519 o P-384, QCE1 es un protocolo propio, etc.; `docs/FIPS_140_3.md`). La ruta TLS con certificados (`tls13.py`) solo ofrece X25519MLKEM768; ML-DSA-87 como firma de certificados TLS no se probó. El nivel lo decide quien llama (las semillas miden lo mismo en los dos niveles), nunca se deduce de la red. Otros conjuntos (ML-KEM-512, ML-DSA-44) no se evaluaron.
- **El handshake `QCE1` es una composición propia** (inspirada en la idea de KEMTLS / X-Wing, **no es** ninguno de ellos y
  **no ha sido revisada por criptógrafos**). Para producción se recomienda TLS 1.3 con el grupo híbrido estándar
  `X25519MLKEM768` (OpenSSL ≥ 3.5) o un protocolo con revisión pública. Ver `decisions/ADRs.md` (ADR-3).
- Vectores oficiales NIST ACVP: keyGen de ML-KEM-768 (25) y ML-DSA-65 (25), sigVer de ML-DSA-65 (15, con casos negativos) y, de SLH-DSA-SHA2-128s, keyGen (10) y sigVer externa pura (14, 12 negativos).
  **No hay vectores de encapsulación/desencapsulación** (la API no permite aleatoriedad fija) ni de ML-DSA sigGen.
  Estos vectores prueban la conformidad de la biblioteca, no la seguridad de la composición de este proyecto.
- Verificación formal **solo simbólica y solo del diseño** (Tamarin, `docs/QCE1_FORMAL.md`): sin modelo computacional, sin capa de registros, sin conformidad modelo-código y sin revisión humana experta. Sin medición de canales laterales. El código Python de control no es de tiempo constante;
  las comparaciones de MAC/hash usan `hmac.compare_digest`.
- El secreto hacia adelante (descarte de la clave KEM efímera) se verifica por revisión de código, no por prueba:
  el mutante correspondiente está declarado equivalente.

## Gestión de claves
- El borrado de memoria en Python es **de mejor esfuerzo**: el intérprete puede haber copiado el secreto (GC, `bytes`
  inmutables devueltas a los consumidores). Para custodia seria del almacén de claves (vault): KMS/HSM vía la interfaz `KeyBackend` (no implementada). La clave privada del servidor TLS sí puede vivir en un token PKCS#11 (`qce/transport/hsm_tls.py`, ver más abajo).
- El vault cifrado (scrypt + ChaCha20-Poly1305) es de laboratorio. El `min_epoch` anti-restauración debe guardarse fuera del vault.
- Los contadores AEAD no se persisten: cada sesión deriva claves nuevas, así que no hay riesgo de reutilización entre sesiones.

## QKD
- **Sin hardware real ni documentación de fabricante.** Solo existe el contrato (`qce/qkd/contract.py`), un registro de
  dispositivos con identidad por desafío-respuesta y un **simulador etiquetado `SIMULATION`**. Su política por defecto lo rechaza.
- **Perfiles de protocolo (`qce/qkd/profiles.py`)**: validan testigos DECLARADOS por el dispositivo (presencia, plausibilidad física,
  umbrales). No verifican la física ni detectan a un equipo que mienta de forma consistente. Ver `docs/QKD_PROTOCOLS.md`.
- Hay un adaptador ETSI GS QKD 014 (`qce/qkd/etsi014.py`), probado SOLO contra un emulador (simulación; ver más abajo), que además se contrastó con una herramienta independiente (`qkdsec`: `docs/ETSI014_ADAPTER.md`, INC-0032/0033); no hay adaptador de ningún fabricante ni KME real: no se inventa compatibilidad (skill `q-crypto-qkd-adapters`, §16).
- Las pruebas son funcionales/de contrato; **no validan la seguridad física de ningún equipo QKD**.
- Mezclar la clave QKD con el secreto poscuántico se hace mediante HKDF sobre el transcript; la composición **no ha sido revisada**
  como diseño de combinación de claves (ver ADR-3). No se afirma que sea "más segura" que PQC sola.

## Aprendizaje y verificación
- **La máquina de estados del workflow registra identidades (`role`, `actor_id`) pero NO las autentica**: es una cadena que
  quien llama afirma. Las aprobaciones críticas sí se verifican por firma (`approval:<ref>` + `approval_verifier`), pero la
  independencia entre implementador y verificador depende de que los `actor_id` sean honestos. Para autenticarlos habría que
  firmar cada transición con la clave del actor (no implementado).
- **Auditoría adversarial independiente realizada (2026-10-17)**: un subagente distinto del implementador encontró 15 hallazgos
  confirmados con PoC (el más grave: la puntuación de mutación era vacía). Todos tienen prueba de regresión en
  `tests/test_audit_findings.py`. Sigue siendo **otra instancia de Claude**, no una auditoría externa humana.
- Las cadenas de hashes (incidentes, tareas, historial, auditoría de claves) detectan manipulación parcial. Quien reescriba
  **toda** la cadena y no haya ancla externa no es detectado.
- El registro de confianza de revisores/aprobadores (`trust/registry.json`) vive en el repositorio. Un agente con permiso de
  escritura podría registrar su propia clave: en producción debe anclarse fuera (HSM, raíz offline, firma humana del registro).
- "Revisión independiente" aquí son identidades distintas con claves distintas. **Si todas las usa la misma instancia de
  Claude, no equivale a una auditoría externa.**
- La prueba de mutación (puntuación en `benchmarks/gates_latest.json`) mide si las pruebas detectan roturas de los
  controles listados en `qce/evolve/mutation.py`, no si existen vulnerabilidades desconocidas.
- La demo (`python -m qce demo`) introduce un fallo **conocido por construcción**; demuestra el ciclo, no la capacidad de
  descubrir fallos desconocidos.
- `pip-audit` necesita red y consulta una base pública. Los hashes de artefactos y el SBOM existen desde 2026-10-19 (`docs/SUPPLY_CHAIN.md`): cubren la sustitución posterior a la publicación, no una dependencia ya maliciosa; las dependencias de prueba no están fijadas con hash.
- El proyecto está bajo control de versiones (repositorio privado `daralaz77/q-crypto-evolve`); los snapshots de `releases/` siguen haciendo de punto de reversión verificado. Un repositorio de Git no sustituye al ancla externa de la raíz de confianza (ver arriba).

## Transporte TLS 1.3 (`qce/transport`)
- Detalle y justificación en `docs/TLS13_TRANSPORT.md`. Lo esencial: Python 3.14 no permite elegir ni leer el grupo; se fija por `OPENSSL_CONF` y se **atestigua**, y solo funciona si el módulo se importa antes que `cryptography`.
- **QKD no está integrado en ESTE transporte** (`qce/transport/tls13.py`, basado en `ssl`: el PSK externo de TLS 1.3 no existe en `ssl` de Python 3.14); va por la ruta PSK con el puente `ctypes` (`tls13_psk.py`, más abajo). La clave privada del servidor vive en el `KeyStore` cifrado (`qce/transport/custody.py`; en claro solo en memoria y en una copia cifrada efímera); con `hsm_tls.py` puede estar en un token PKCS#11 (probado solo con SoftHSM). La rotación no es automática (hay que llamar a `rotate_if_due`) y la revocación es por CRL explícita (sin OCSP).


## Capa interna QKD sobre TLS (QIL1, `qce/transport/qkd_layer.py`) — NO REVISADA
- Composición propia escrita por instancias de Claude; ninguna persona experta la ha revisado. El paquete de revisión externa actual (`python -m qce review-package`) sí incluye su especificación, modelo formal y comprobador de conformidad, pero ninguna persona lo ha revisado.
- Es una cascada (TLS por fuera, QIL1 por dentro), no una mezcla en el calendario de claves de TLS. La ligadura usa `tls-unique`, que en TLS 1.3 no es estándar (RFC 9266 no está disponible en Python).
- Modelo Tamarin simbólico (`formal/qil1.spthy`): no cubre la capa de registros, la física de QKD, unknown-key-share con varios servidores ni KCI estricto, y **acota los abortos a uno por clave** para terminar. Hay conformidad por trazas (`docs/QKD_LAYER_CONFORMANCE.md`, 7 sesiones), no una prueba del código.
- Sin secreto hacia adelante propio; sin HSM; la clave QKD es simulada (`os.urandom`), no hay hardware real.
- Un tercero que conozca un identificador de clave ya no puede gastarla (reserva/liberación), pero puede retenerla hasta `HANDSHAKE_TIMEOUT`; sin límite de tasa por origen.

## TLS 1.3 con PSK externa (`qce/transport/tls13_psk.py`) — puente NO REVISADO
- Es la ruta QKD recomendada, pero el **puente `ctypes`** hacia `libssl` es código nuestro sin revisión humana (tipos C, callbacks, propiedad de `SSL_SESSION`); hubo ya un defecto real (cola de errores por hilo, corregido). Detalle en `docs/TLS13_PSK_TRANSPORT.md` §4.
- Necesita OpenSSL ≥ 3.5 (falla cerrado si no); probado en macOS (Homebrew), en Debian 13 arm64 NATIVO (suite completa 2026-10-22: 581 pasan, 27 saltadas, 0 fallos) en Debian 13 x86_64 EMULADO con Docker (580 pasan, 1 falla: un fallo intermitente con GnuTLS 3.8.9, INC-0029) y, desde 2026-10-27, la batería completa en Debian 13 x86_64 y arm64 NATIVOS en la CI de GitHub Actions (OpenSSL 3.5.7, GnuTLS 3.8.9): pasa sin fallos y la prueba de GnuTLS repetida 100 veces por arquitectura dio 0 fallos en 500 pruebas, por lo que INC-0029 se cerró atribuyéndolo, como PROBABLE y sin mecanismo demostrado, a la emulación; una tasa de fallo muy baja no queda descartada, y la CI sigue vigilándolo en cada push. No probado en Windows. El identificador de clave es visible en el ClientHello. Clave QKD simulada.
- La corrección de OpenSSL/TLS 1.3 se asume; no se reprodujo su análisis formal.
- Rotación automática: hay que llamar a `rotate_if_due` periódicamente (sin planificador). Revocación: CRL explícita (sin OCSP, sin distribución automática; sin `crl_file` el cliente no comprueba).
- **HSM por PKCS#11** (`docs/HSM.md`): la ruta con certificados puede tener la clave en un token (`qce/transport/hsm_tls.py`), probado SOLO con SoftHSM (RSA-PSS); ningún HSM real, ni ML-DSA en el token; un archivo de configuración de HSM por proceso; revocar = reiniciar. Puente sin revisión humana. Sin esta ruta, Python `ssl` sigue exigiendo la clave en el proceso; en la ruta PSK no existe clave privada de larga duración.

## Adaptador ETSI GS QKD 014 y SLH-DSA
- El adaptador 014 (`docs/ETSI014_ADAPTER.md`) **no se ha probado con ningún KME real**, solo con un emulador que es simulación. La interfaz solo entrega claves: la garantía es la confianza en el operador del KME y en la ficha aprobada, nunca física. Una clave por petición; sin extensiones de fabricantes.
- SLH-DSA (`docs/SLHDSA.md`) usa el `libcrypto` del sistema por un puente `ctypes` NO REVISADO; los vectores oficiales ACVP de SLH-DSA-SHA2-128s sí se ejecutaron (keyGen 10/10, sigVer externa pura 14/14; no sigGen ni preHash ni otros conjuntos de parámetros); no está integrada en el apretón ni en las declaraciones firmadas.

## Fuzzing y carga de los puentes
- Resultados y límites en `docs/FUZZ_Y_CARGA.md`: sin defectos por fuzzing, una fuga real de SLH-DSA corregida (INC-0023), memoria/descriptores/hilos estables. Fuzzing no guiado por cobertura. Probado en macOS (Homebrew), en Debian 13 arm64 nativo y en Debian 13 x86_64 emulado (OpenSSL 3.5.7); la batería completa también pasa en x86_64 y arm64 nativos en CI, pero las mediciones de fuga y carga de este documento no se repitieron allí; no en Windows. En glibc la fuga se mide con los bytes EN USO (`mallinfo2`), no con el RSS: en x86_64 el RSS crecía ≈ 600 B por apretón por fragmentación sin que hubiera fuga (INC-0030).
- La interoperabilidad con una segunda implementación (GnuTLS 3.8.13) cubre solo el grupo clásico X25519 (GnuTLS no trae el híbrido); el parámetro `group="X25519"` existe solo para eso. Detalle en `docs/TLS13_PSK_TRANSPORT.md` §3b.
- **Segunda implementación del híbrido: Mozilla NSS 3.125** (`docs/TLS13_PSK_TRANSPORT.md` §3c), en los dos sentidos de la PSK y con certificados, incluido el servidor con la clave en el HSM, con X25519MLKEM768. LÍMITES: `selfserv` de NSS no aplica la PSK en el servidor, así que el sentido «nuestro cliente PSK ↔ servidor NSS» usa un ayudante en C nuestro (`tests/helpers/nss_psk_server.c`) sobre la biblioteca de NSS y necesita un certificado configurado; la suite por defecto SHA-384 no interopera con NSS (PSK ligada a SHA-256); solo macOS/Homebrew. Ninguna de estas pilas es una auditoría.

## FIPS 140-3 / CNSA 2.0
- **No se puede afirmar** FIPS 140-3 ni CNSA 2.0 (`docs/FIPS_140_3.md`, solo análisis, nada ejecutado: este equipo no tiene proveedor FIPS). Razones: no hay módulo OpenSSL validado con ML-KEM (3.5.8 está en revisión del CMVP, 2026-10-20); el híbrido lleva X25519, que NIST no propone aprobar; ML-KEM-768/ML-DSA-65 no son los parámetros de CNSA 2.0 (1024/87); QCE1/QIL1 son protocolos propios; el código usa ChaCha20-Poly1305 y scrypt. Varios datos del análisis están marcados como no re-verificados. **Alcance fijado (2026-10-22):** cualquier reclamo FIPS aplicaría solo a TLS 1.3 estándar con suite AES-GCM (PSK, certificado o HSM); QCE1, QIL1 y el vault quedan fuera y siguen usando ChaCha20-Poly1305 y scrypt a propósito (cambiarlos rompe formatos de protocolo y archivos; ver `docs/FIPS_140_3.md` §4b). Un modo aprobado opcional queda para cuando exista un módulo validado con ML-KEM.

## HSM en la nube (kit preparado, NO probado)
- `docs/hsm_cloud/` prepara la prueba con Google Cloud KMS (protección HSM) + una VM Linux amd64: la biblioteca PKCS#11 de Google solo existe para Linux y Windows, no macOS. **No se ha ejecutado contra Google**: solo la lógica de `verify_kms.py` se probó con SoftHSM. Riesgos abiertos: si la clave pública `RSA_SIGN_PSS` sirve como certificado TLS, compatibilidad con `pkcs11-provider`, latencia por apretón y `fork`. Está fuera de las puertas a propósito.

## Panel y demo guiada (`panel/`, `site/`)
- Son herramientas de **presentación**, fuera del hash del `release_id` y fuera de las puertas G1–G6: sus pruebas (`panel/tests`, `site/tests`) corren aparte y en CI, pero no cuentan en G2 ni están cubiertas por la prueba de mutación.
- El panel es de solo lectura y local; no verifica firmas ni la integridad de `qce/` más allá de recalcular el `release_id`. Lo que muestra no sustituye a `python -m qce gates`.
- La demo muestra trazas grabadas de una simulación (KME emulado): no es una medición de QKD real ni una revisión del código.

