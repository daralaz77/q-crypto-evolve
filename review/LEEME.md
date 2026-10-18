# Paquete de revisión externa — QCE1 y QIL1

Gracias por mirar esto. Este paquete reúne todo lo necesario para revisar **un protocolo de apretón de manos híbrido poscuántico (QCE1)** sin tener que preguntar nada al autor.
Se pide una revisión crítica: lo más útil es **encontrar lo que está mal**, no confirmar lo que está bien.

## 1. Qué es QCE1 (cinco líneas)

Un apretón de manos de 4 mensajes entre un cliente y un servidor con **identidad fijada**. Intercambio de claves híbrido X25519 + ML-KEM-768 (KEM efímero del servidor),
firma híbrida Ed25519 + ML-DSA-65 del servidor (deben verificar ambas), claves derivadas con HKDF-SHA256 sobre el hash del transcript, confirmación de clave con HMAC en
ambos sentidos y una capa de registros AEAD con contador. Opcionalmente se mezcla una clave QKD. **No hay autenticación del cliente** (no objetivo declarado).

## 1b. Qué es QIL1 (añadido 2026-10-17)

Una **segunda composición propia**, independiente de QCE1: una capa interna con **clave QKD** que corre DENTRO de una conexión TLS 1.3 con `X25519MLKEM768` ya establecida, ligada a esa sesión
(valor `tls-unique` + huella del certificado del servidor), con confirmación mutua por MAC y registros ChaCha20-Poly1305. Existe porque ningún TLS accesible desde Python permite una PSK externa en TLS 1.3.
Archivos: `docs/QKD_LAYER_SPEC.md`, `docs/QKD_LAYER_FORMAL.md`, `docs/QKD_LAYER_CONFORMANCE.md`, `formal/qil1.spthy`, `qce/transport/qkd_layer.py`, `tests/test_qkd_layer.py`, `tests/test_qil_conformance.py`. También se incluyen
`docs/TLS13_TRANSPORT.md` (transporte) y `docs/QKD_TLS_OPTIONS.md` (las tres opciones estudiadas). Preguntas específicas: sección E de `PREGUNTAS_ABIERTAS.md`. La clave QKD es **simulada**.

## 2. Estado y transparencia (léase antes de nada)

- **Es un laboratorio, no un producto.** QCE1 es una composición propia, inspirada en ideas de KEMTLS y de combinadores de KEM, **sin revisión pública previa**.
  Nuestra recomendación de producción es TLS 1.3 con `X25519MLKEM768`; este paquete existe para poder decidir con criterio si QCE1 merece seguir.
- **Toda la autoría es de instancias de Claude (IA):** el código, la especificación, el modelo formal y las pruebas. Hubo **dos auditorías adversariales internas** hechas por otras instancias de Claude (encontraron 15 y 12 fallos, todos corregidos y con prueba de regresión).
  Eso **no es** una revisión humana independiente: esa es justamente la que se pide aquí.
- Ninguna persona experta ha revisado hasta ahora la especificación, el modelo ni el código.
- Las debilidades que ya conocemos están en `LIMITATIONS.md` y en `PREGUNTAS_ABIERTAS.md`.

## 3. Qué se pide (de mayor a menor valor)

| Nivel | Qué | Dónde |
|---|---|---|
| **A. Diseño** | ¿El protocolo cumple sus objetivos con el modelo de atacante declarado? ¿Hay ataques que el modelo no captura? | `docs/QCE1_SPEC.md`, `PREGUNTAS_ABIERTAS.md` |
| **B. Modelo y conformidad** | ¿El modelo de Tamarin modela lo que dice? ¿Faltan propiedades (UKS, KCI, revelación de claves de sesión)? ¿La conformidad con el código es convincente? | `formal/qce1.spthy`, `docs/QCE1_FORMAL.md`, `docs/QCE1_CONFORMANCE.md` |
| **D. QIL1** | ¿La ligadura a `tls-unique` es suficiente en TLS 1.3? ¿Falta algún lema (UKS con varios servidores, KCI)? ¿La reserva/liberación y la cota de un aborto del modelo son aceptables? | `docs/QKD_LAYER_SPEC.md`, `formal/qil1.spthy` |
| **C. Código crítico** | Lectura de `qce/protocols/session.py`, `qce/pqc/hybrid.py`, `qce/symmetric/aead.py`, `qce/core/encoding.py` frente a la especificación | `qce/` |

Si solo tiene tiempo para una cosa: **nivel A**, y dentro de él las preguntas 1 a 4 de `PREGUNTAS_ABIERTAS.md`.

## 4. Qué NO se pide

- Revisar ML-KEM, ML-DSA, X25519, Ed25519, HKDF, ChaCha20-Poly1305 o AES-GCM como primitivas: se asumen seguras (biblioteca `cryptography` 50.0.2).
- Auditar el resto del repositorio (gestión de claves, gobierno de versiones, QKD simulado): está fuera de este alcance.
- Certificación ni cumplimiento (FIPS 140-3, CNSA 2.0).

## 5. Orden de lectura recomendado

1. Este archivo y `LIMITATIONS.md`.
2. `docs/QCE1_SPEC.md` completo: notación, mensajes, derivación, propiedades (§11) y preguntas (§13).
3. `PREGUNTAS_ABIERTAS.md`.
4. `docs/QCE1_FORMAL.md` y `formal/qce1.spthy`.
5. `docs/QCE1_CONFORMANCE.md`.
6. El código (`qce/protocols/session.py` es el archivo central).
7. `REPRODUCCION.md` para ejecutar todo usted mismo.

## 6. Cómo entregar el informe

Use `PLANTILLA_INFORME.md`. Basta con texto; si prefiere comentar sobre los archivos, también vale. Se agradece distinguir **hallazgo confirmado**, **sospecha** y **pregunta**.
Si encuentra algo grave, avísenos por el canal acordado antes de publicarlo: **[CONTACTO — a completar por quien envía el paquete]**.

## 7. Integridad del paquete

`MANIFEST.sha256` lista el SHA-256 de cada archivo. `python -m qce review-package --verify <paquete.zip>` (o `shasum -a 256 -c MANIFEST.sha256`) lo comprueba.
El paquete **no está firmado** todavía: la firma humana del remitente está pendiente; hasta entonces el hash del `.zip` debe comunicarse por un canal aparte.
