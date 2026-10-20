# Registro de decisiones (ADR)

## ADR-1 — Biblioteca: `cryptography` 50.0.2 (OpenSSL 4.0.3 embebido)
Contexto: hace falta ML-KEM/ML-DSA mantenidos y probados. Alternativas: liboqs (no instalada, requiere compilar),
kyber-py/dilithium-py (Python puro, didácticos, no constantes en tiempo), OpenSSL por CLI (secretos en ficheros/procesos).
Decisión: `cryptography` ≥ 50 (API `mlkem`/`mldsa`, semillas deterministas para vectores). Versión fijada en `requirements.lock`.
Consecuencia: sin SLH-DSA. Actualización de la dependencia = cambio de nivel 2 (revisión).

## ADR-2 — KEM híbrido X25519 + ML-KEM-768
El secreto final es HKDF-SHA256(ss_mlkem ‖ ss_x25519, etiqueta ‖ texto cifrado ‖ clave pública del receptor).
Motivo: seguro si al menos uno de los dos componentes resiste; el enlace al texto cifrado y a la clave pública evita
ataques de recombinación. Probado por `test_combiner_depends_on_every_input` y los mutantes `kem-combiner-*`.
Limitación: es una composición propia con la misma intención que X-Wing/TLS híbrido, no idéntica.

## ADR-3 — Handshake `QCE1` propio, solo para laboratorio
Porque el entorno no incluye una pila TLS con grupos híbridos controlable desde Python. Decisión: implementarlo
mínimo, con transcript firmado, KEM efímero, confirmación de clave y anti-degradación, y **declararlo no revisado**.
Recomendación para producción: TLS 1.3 + `X25519MLKEM768`. Cambiar el protocolo es nivel 3 (autorización humana).

## ADR-4 — Evolución solo con puertas y trinquete
Las puertas G1–G6 (`qce/evolve/gates.py`) deciden el estado. Los umbrales solo pueden endurecerse (G1 compara con el
historial). Tocar `gates.json`, `chainlog.py`, escáneres o `learning/` es nivel 3. Ningún agente entra en
`RELEASE_APPROVED`.

## ADR-5 — QKD: contrato + broker, simulador etiquetado, fallar cerrado
El núcleo solo ve el `KeyBroker`. La confianza en el dispositivo se reevalúa en cada operación. Sin fallback silencioso.
Un adaptador real exige documentación y hardware autorizados que no existen en este entorno (skill `q-crypto-qkd-adapters`).

## ADR-6 — Transporte de producción: TLS 1.3 con X25519MLKEM768, con atestación y falla cerrado
Decisión: adoptar TLS 1.3 con el grupo híbrido estándar como transporte recomendado (opción A del ADR-3); QCE1 queda como banco de pruebas y como vía de investigación para el modo QKD.
Implementación: `qce/transport/tls13.py`. Como `ssl` de Python 3.14 no permite elegir ni leer el grupo, los grupos se fijan por configuración de OpenSSL y se **atestiguan** en ejecución (par clásico = no conecta); si la atestación falla, no hay transporte.
Consecuencia: se pierde, de momento, la mezcla de clave QKD (el PSK externo de TLS 1.3 no está disponible en `ssl` de Python 3.14). Verificado en este equipo: grupo negociado confirmado por `openssl s_client`; certificado ML-DSA-65 funcional.

## ADR-7 — La clave privada TLS se custodia en el KeyStore, no en un archivo
Decisión: la clave nace en `TlsKeyCustody` (propósito `TLS` del KeyStore), la CA recibe una CSR, y la clave solo sale para construir un `SSLContext` mediante una copia cifrada y efímera (contraseña solo en memoria). Rotación = nueva clave + certificado y la anterior a RETIRED; revocación = borrado del secreto + `stop_accepting()`.
Alternativas descartadas: `memfd_create`/descriptores anónimos (no hay equivalente portátil en macOS y `ssl` exige una ruta), y mantener un `.key` en claro con permisos 0600.
Consecuencia: en disco nunca hay una clave privada en claro; en memoria sí. El cierre completo exige un HSM o un agente de claves.
Hallazgo durante la implementación: `secrets`, `hmac` y `hashlib` de la biblioteca estándar inicializan OpenSSL al importarse y anulan la configuración del grupo híbrido si se importan antes que `qce.transport.tls13`; la atestación lo detecta y el módulo falla cerrado (INC-0021).


## ADR-8 — Capa interna QKD sobre TLS 1.3 (QIL1), declarada NO REVISADA
Decisión: aplicar la clave QKD dentro del canal TLS (opción B de `docs/QKD_TLS_OPTIONS.md`), con derivación ligada a la sesión TLS (`tls-unique` + huella del certificado), confirmación mutua por MAC y registros AEAD propios. Módulo `qce/transport/qkd_layer.py`, especificación `docs/QKD_LAYER_SPEC.md`, modelo `formal/qil1.spthy`.
Por qué: la opción A (PSK externa en TLS 1.3) no existe en `ssl` de Python 3.14. Es una composición propia: **no está revisada por ninguna persona** y no sustituye a la opción A cuando una pila la soporte.
Alternativas descartadas: reutilizar QCE1 (reintroduce un handshake propio completo) y mezclar la clave QKD en la sal de TLS (imposible desde Python).
Consecuencias: cascada de dos cifrados, no combinador; depende de un valor de ligadura no estándar en TLS 1.3; sin secreto hacia adelante propio. El modelo formal muestra que sin la ligadura un certificado falso con retransmisión sí funciona.

### ADR-8, adenda (2026-10-17) — reserva en lugar de consumo al recibir el HELLO
El primer diseño consumía la clave al recibir el HELLO (modelo y código coherentes) y dejaba a cualquiera que conociera el identificador gastarla (T43). Decisión: el servidor **reserva** la clave, la **consume solo si el cliente la demuestra** y la **libera** si el apretón falla o caduca (`HANDSHAKE_TIMEOUT`). Para el broker se añadieron `hold`/`peek`/`release`.
Coste: el modelo necesita una cota (un aborto por clave) para que Tamarin termine, y un atacante puede retener la clave hasta el plazo. Alternativa descartada: límite de tasa por IP (no impide el gasto con varias IP y no cambia la semántica de consumo).

## ADR-9 — La ruta QKD recomendada es TLS 1.3 con PSK externa vía puente ctypes; QIL1 pasa a alternativa
Decisión: usar la PSK externa de TLS 1.3 de OpenSSL (opción A de `docs/QKD_TLS_OPTIONS.md`) mediante `qce/transport/tls13_psk.py`, con la clave QKD derivada a PSK por HKDF. QIL1 (ADR-8) se conserva para pilas sin PSK externa.
Por qué: el protocolo es estándar y de una implementación muy usada; lo propio queda reducido a un puente de FFI y a la preparación de la clave. Ventaja extra: no hay clave privada de larga duración ni certificados en esta ruta.
Alternativas descartadas: `openssl s_server`/`s_client` como subprocesos (la PSK iría por la línea de órdenes, visible en `ps`); esperar a un `ssl` de Python con PSK (no hay fecha).
Consecuencias: dependencia de la ruta de `libssl` ≥ 3.5; el puente es código delicado sin revisión; el `kid` es visible. HSM: no viable desde `ssl` de Python (ver `docs/TLS13_PSK_TRANSPORT.md` §5).

## ADR-10 — ETSI GS QKD 014 como perfil de confianza en el operador, no de garantía física
Decisión: el adaptador 014 se registra con un perfil propio (`ETSI-014-KME`) que no pide QBER, ε ni amplificación (la interfaz no los da), pide el tamaño de clave y la ficha aprobada (saltos de confianza), y su identidad es el certificado fijado en el alta.
Por qué: inventar testigos que la interfaz no ofrece, o usar los de BB84, sería afirmar una garantía que no existe (principio de la skill de adaptadores). Coste: el broker distingue ahora perfiles con testigos por clave y sin ellos (`per_key_witnesses`), y `evaluate` toma los saltos de la ficha cuando el perfil no los reporta.
Consecuencia: probado solo contra un emulador (simulación declarada); ningún KME real. SLH-DSA (ADR sin número, `docs/SLHDSA.md`): se añade como primitiva por el `libcrypto` del sistema, no integrada en el protocolo.

## ADR-11 — La firma humana tiene una ceremonia propia, y es lo único que puede abrir G5/G6
Decisión: `identity new/register` y `sign` (`qce/evolve/ceremony.py`): la persona crea su clave fuera del repositorio, la registra (sin que eso apruebe nada) y firma una declaración ligada al `release_id`; la CLI exige terminal interactiva. Ninguna parte de la ceremonia la ejecuta un agente con una clave que sea suya.
Por qué: las puertas dependían de una API de Python sin interfaz de uso, así que en la práctica nadie podía firmar. Límite: el registro de confianza sigue en el repositorio (LIMITATIONS.md) y la variable de entorno de pruebas existe; la defensa es confirmar la huella por otro canal.

## ADR-12 — Cadena de suministro: hashes de dependencias y SBOM, con una excepción autorizada del escáner de secretos
Decisión: `requirements.hashes.txt` (SHA-256 de todos los archivos publicados) y `sbom.cdx.json` (CycloneDX 1.5 determinista) junto al lock, coherencia comprobada en G1 (`qce/evolve/supply_chain.py`).
El escáner de secretos marcaba los hashes públicos del SBOM; tocar el escáner es nivel 3, así que se preguntó al usuario (2026-10-20), que **autorizó una excepción explícita** (`sbom.cdx.json`, regla `long-hex-literal`) frente a guardar el SBOM en XML para que el escáner no lo leyera.
Consecuencia: el escáner sigue revisando todo lo demás; la excepción queda escrita con su motivo en `SECRET_ALLOW`. Probado con una instalación limpia `--require-hashes` y una alterada rechazada (`docs/SUPPLY_CHAIN.md`).

## ADR-13 — Clave del servidor TLS en un HSM por PKCS#11 (pkcs11-provider), probada con SoftHSM
Decisión: `qce/transport/hsm_tls.py` carga `pkcs11-provider` en un contexto de biblioteca de OpenSSL propio y entrega la clave privada del token (por URI) a `SSL_CTX_use_PrivateKey`; falla cerrado y sin alternativa en software. Se descartó la ruta por `ssl` de Python (exige la clave en el proceso) y un agente de claves propio (inventar protocolo).
Hallazgos que fijaron el diseño: el contexto de biblioteca no se puede liberar mientras haya `fork()` (INC-0027); SoftHSM solo firma RSA de forma fiable (las pruebas usan RSA-PSS).
Consecuencia: la clave larga del servidor deja de estar en el proceso, pero solo se demostró el mecanismo con SoftHSM; la lista de lo no probado está en `docs/HSM.md`. El proveedor se compila con un guion reproducible que fija su SHA-256 (`docs/hsm_lab/setup.sh`).

## ADR-14 — Reestructuración sin cambio de comportamiento (2026-10-20)
Decisión: cinco refactores medidos, cada uno con sus pruebas y mutantes antes de pasar al siguiente. (1) la carga de OpenSSL por `ctypes` sale de `transport/tls13_psk.py` a `core/openssl_ffi.py` (la usan PSK, HSM y SLH-DSA; rompe el ciclo `pqc → transport → qkd → pqc`); (2) un solo `lp()` de producción en `core/encoding.py`; (3) `gates.evaluate` en una función por puerta con un contexto, y `cli.main` en un subcomando por función; (4) los 361 mutantes pasan de `evolve/mutation.py` a datos por familia en `evolve/mutants/` (mismo conjunto, comprobado campo a campo); (5) `approvals.py` pasa de `evolve` a `security`, lo que elimina el ciclo `evolve ↔ recovery` y sus importaciones tardías.
Se mantuvo A PROPÓSITO fuera de la unificación `qil_conformance.lp` y el `lp` de las pruebas: son un segundo observador independiente, y unificarlos quitaría la capacidad de detectar un error en el `lp` de producción.
Consecuencia: el grafo de dependencias entre paquetes ya no tiene ciclos; el `release_id` cambia, así que las firmas previas no valen y hay que volver a firmar. Efecto en pruebas: cinco pruebas cambian solo el objeto parcheado (`openssl_ffi` en vez de `tls13_psk`, `security.approvals` en vez de `evolve.approvals`); ninguna aserción se debilitó.
