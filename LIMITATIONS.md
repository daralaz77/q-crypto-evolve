# Limitaciones y lo que NO se ha demostrado

Este documento es parte del producto. Un resultado "verde" solo significa lo que la prueba comprueba.

## Estado real (Q-Crypto Evolve v0.3-lab, 2026-10-17)
- **Laboratorio.** No hay despliegue, no hay claves de producción, no hay auditoría externa.
- **Estado máximo alcanzable por el sistema:** `VERIFIED`. `RELEASE_APPROVED` exige firma humana (GATE 6) y no se simula.

## Criptografía
- Primitivas: ML-KEM-768 (FIPS 203), ML-DSA-65 (FIPS 204), X25519, Ed25519, ChaCha20-Poly1305 / AES-256-GCM de
  `cryptography` 50.0.2 (OpenSSL 4.0.3 embebido). No se implementó ninguna primitiva propia.
- **SLH-DSA no está incluido**: esta versión de `cryptography` no lo expone. Declarado, no simulado.
- **Solo ML-KEM-768 / ML-DSA-65.** Otros conjuntos de parámetros no se han evaluado.
- **El handshake `QCE1` es una composición propia** (inspirada en la idea de KEMTLS / X-Wing, **no es** ninguno de ellos y
  **no ha sido revisada por criptógrafos**). Para producción se recomienda TLS 1.3 con el grupo híbrido estándar
  `X25519MLKEM768` (OpenSSL ≥ 3.5) o un protocolo con revisión pública. Ver `decisions/ADRs.md` (ADR-3).
- Vectores oficiales NIST ACVP: keyGen de ML-KEM-768 (25) y ML-DSA-65 (25) y sigVer de ML-DSA-65 (15, con casos negativos).
  **No hay vectores de encapsulación/desencapsulación** (la API no permite aleatoriedad fija) ni de ML-DSA sigGen.
  Estos vectores prueban la conformidad de la biblioteca, no la seguridad de la composición de este proyecto.
- Verificación formal **solo simbólica y solo del diseño** (Tamarin, `docs/QCE1_FORMAL.md`): sin modelo computacional, sin capa de registros, sin conformidad modelo-código y sin revisión humana experta. Sin medición de canales laterales. El código Python de control no es de tiempo constante;
  las comparaciones de MAC/hash usan `hmac.compare_digest`.
- El secreto hacia adelante (descarte de la clave KEM efímera) se verifica por revisión de código, no por prueba:
  el mutante correspondiente está declarado equivalente.

## Gestión de claves
- El borrado de memoria en Python es **de mejor esfuerzo**: el intérprete puede haber copiado el secreto (GC, `bytes`
  inmutables devueltas a los consumidores). Para custodia seria: KMS/HSM vía la interfaz `KeyBackend` (no implementada).
- El vault cifrado (scrypt + ChaCha20-Poly1305) es de laboratorio. El `min_epoch` anti-restauración debe guardarse fuera del vault.
- Los contadores AEAD no se persisten: cada sesión deriva claves nuevas, así que no hay riesgo de reutilización entre sesiones.

## QKD
- **Sin hardware real ni documentación de fabricante.** Solo existe el contrato (`qce/qkd/contract.py`), un registro de
  dispositivos con identidad por desafío-respuesta y un **simulador etiquetado `SIMULATION`**. Su política por defecto lo rechaza.
- **Perfiles de protocolo (`qce/qkd/profiles.py`)**: validan testigos DECLARADOS por el dispositivo (presencia, plausibilidad física,
  umbrales). No verifican la física ni detectan a un equipo que mienta de forma consistente. Ver `docs/QKD_PROTOCOLS.md`.
- No hay adaptador ETSI GS QKD 014 ni de fabricante alguno: no se inventa compatibilidad (skill `q-crypto-qkd-adapters`, §16).
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
- `pip-audit` necesita red y consulta una base pública; `requirements.lock` no fija hashes de artefactos.
- El proyecto no está bajo control de versiones en esta carpeta; los snapshots de `releases/` hacen de punto de reversión.

## Transporte TLS 1.3 (`qce/transport`)
- Detalle y justificación en `docs/TLS13_TRANSPORT.md`. Lo esencial: Python 3.14 no permite elegir ni leer el grupo; se fija por `OPENSSL_CONF` y se **atestigua**, y solo funciona si el módulo se importa antes que `cryptography`.
- **QKD no está integrado en este transporte** (el PSK externo de TLS 1.3 no existe en `ssl` de Python 3.14). La clave privada del servidor vive ahora en el `KeyStore` cifrado (`qce/transport/custody.py`; en claro solo en memoria y en una copia cifrada efímera), pero **no en un HSM**, la rotación no es automática y no hay revocación de certificados (CRL/OCSP).


## Capa interna QKD sobre TLS (QIL1, `qce/transport/qkd_layer.py`) — NO REVISADA
- Composición propia escrita por instancias de Claude; ninguna persona experta la ha revisado. El paquete de revisión externa (`dist/`) es anterior y **no la incluye**.
- Es una cascada (TLS por fuera, QIL1 por dentro), no una mezcla en el calendario de claves de TLS. La ligadura usa `tls-unique`, que en TLS 1.3 no es estándar (RFC 9266 no está disponible en Python).
- Modelo Tamarin simbólico (`formal/qil1.spthy`): no cubre la capa de registros, la física de QKD, unknown-key-share ni KCI, y **no hay conformidad código-modelo** para QIL1.
- Sin secreto hacia adelante propio; sin HSM; la clave QKD es simulada (`os.urandom`), no hay hardware real.
- Un tercero que conozca un identificador de clave puede gastarla (denegación de servicio); sin límite de tasa.
