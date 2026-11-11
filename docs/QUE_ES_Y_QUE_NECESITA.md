# Q-Crypto Evolve — qué es, qué no es y qué necesitamos / what it is, what it is not, what we need

*Español primero; English below.*

## Español

**Qué es.** Un laboratorio de criptografía poscuántica (ML-KEM, ML-DSA, SLH-DSA, X25519/Ed25519) con dos composiciones propias: el apretón de manos híbrido **QCE1** y la capa interna con clave QKD **QIL1**. Incluye especificaciones, modelos formales simbólicos (Tamarin), conformidad con el código, pruebas (936), prueba de mutación (463 de 463 mutantes puntuables detectados) y un sistema de puertas con firma humana.

**Qué NO es.**
- No es un producto ni está listo para producción. No hay despliegue, ni claves de producción, ni auditoría externa.
- **Autoría compartida:** el proyecto lo dirige y coautora **Darwing John Pérez Aranguren (prompt engineer)**, que aportó los requisitos, las decisiones de diseño y la dirección; el **código, la especificación, los modelos formales y las pruebas fueron escritos por instancias de Claude (IA)** a partir de esas indicaciones. Las revisiones internas las hicieron otras instancias de Claude. **Ninguna persona experta independiente ha revisado QCE1 ni QIL1.**
- QCE1 y QIL1 son composiciones propias, no estándares. Para producción recomendamos TLS 1.3 con `X25519MLKEM768` o protocolos con revisión pública.
- La clave QKD es simulada: no hay hardware real.
- Una prueba en verde significa solo lo que la prueba comprueba (`LIMITATIONS.md`).

**Qué necesitamos.** Críticas, no aplausos. En orden de valor:
1. Revisión de diseño de QCE1/QIL1 por alguien con experiencia en protocolos y verificación formal.
2. Respuestas a preguntas concretas (`review/PREGUNTAS_ABIERTAS.md`), por ejemplo: ¿basta HKDF con sal `th` para separar dominios? ¿es suficiente `tls-unique` como ligadura en TLS 1.3? ¿faltan lemas de *unknown-key-share* o KCI?
3. Una auditoría independiente (se estima entre 9.000 y 13.650 EUR según cotizaciones de firmas externas) del puente TLS 1.3 PSK, la integración PKCS#11/HSM y el cliente ETSI 014. Sigue sin financiación (`funding.json`).

**Por dónde empezar.** `review/RESUMEN_1_PAGINA.md` (una página) y `review/LEEME.md`. Todo lo que se afirma como comprobado tiene su límite escrito en `LIMITATIONS.md`.

**Cómo avisar de un fallo.** `SECURITY.md` (divulgación coordinada de 90 días).

## English

**What it is.** A post-quantum cryptography lab (ML-KEM, ML-DSA, SLH-DSA, X25519/Ed25519) with two home-grown compositions: the hybrid handshake **QCE1** and the inner QKD-keyed layer **QIL1**. It ships specifications, symbolic formal models (Tamarin), code conformance checks, 936 tests, mutation testing (463 of 463 scorable mutants detected) and a gate system with a human signature.

**What it is NOT.**
- Not a product and not production-ready: no deployment, no production keys, no external audit.
- **Shared authorship:** the project is directed and co-authored by **Darwing John Pérez Aranguren (prompt engineer)**, who provided the requirements, the design decisions and the direction; the **code, specification, formal models and tests were written by Claude (AI) instances** from those instructions. The internal reviews were done by other Claude instances. **No independent human expert has reviewed QCE1 or QIL1.**
- QCE1 and QIL1 are our own compositions, not standards. For production we recommend TLS 1.3 with `X25519MLKEM768` or a protocol with public review.
- The QKD key is simulated: no real hardware.
- A green test only means what the test checks (`LIMITATIONS.md`).

**What we need.** Criticism, not applause, in this order:
1. A design review of QCE1/QIL1 by someone experienced in protocols and formal verification.
2. Answers to specific questions (`review/PREGUNTAS_ABIERTAS.md`), e.g. is HKDF with salt `th` enough for domain separation? Is `tls-unique` an acceptable channel binding in TLS 1.3? Are unknown-key-share or KCI lemmas missing?
3. An independent audit (quotes from external firms range from 9,000 to 13,650 EUR) of the TLS 1.3 PSK bridge, the PKCS#11/HSM integration and the ETSI 014 client. Still unfunded (`funding.json`).

**Where to start.** `review/RESUMEN_1_PAGINA.md` (one page) and `review/LEEME.md`. Every claim of verification has its limit written down in `LIMITATIONS.md`.

**How to report a flaw.** `SECURITY.md` (90-day coordinated disclosure).
