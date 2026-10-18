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
