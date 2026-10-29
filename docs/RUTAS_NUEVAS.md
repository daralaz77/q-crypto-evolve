# Rutas criptográficas nuevas para Q-Crypto Evolve

Fecha: 2026-10-29. Complementa `docs/COMPARATIVA_PQC.md` (herramientas y brechas ya identificadas): aquí van **caminos que el proyecto aún no ha tomado**, con la brecha real de nuestro repositorio que cada uno cerraría.

## Método y límites
- Búsqueda web en una sesión (10 consultas). **No leí ningún documento primario** (RFC, ETSI, NIST) de esta lista: todo viene de resúmenes, borradores indexados y blogs. Etiquetas: **[PROBABLE]** = varias fuentes coherentes; **[HIPÓTESIS]** = mi razonamiento o dato contradictorio; **[NO VERIFICADO]** = la búsqueda no lo cubrió.
- Muchos de estos elementos son **borradores del IETF** (pueden cambiar o caducar) o **investigación**. «Ruta» no significa «estándar listo».
- Nada de esto se ha implementado ni medido aquí.

## 1. Rutas, ordenadas por lo que más aporta a *nuestro* sistema

| # | Ruta | Brecha nuestra que cerraría (hecho del repo) | Madurez | Esfuerzo | ¿Toca `qce/` (cambia `release_id`)? |
|---|---|---|---|---|---|
| R1 | **Ancla externa del libro de incidentes y del registro de confianza**: publicar periódicamente la cabeza de la cadena en un registro de transparencia o sellado externo (GitHub attestations, RFC 3161, OpenTimestamps; Rekor v2 usa teselas `tlog-tiles` y puntos de control firmados) | LIMITATIONS: «quien reescriba **toda** la cadena y no haya ancla externa no es detectado» y «el registro de confianza vive en el repositorio» | **[PROBABLE]** Rekor v2 y OpenTimestamps existen; los borradores de anclaje temporal (`draft-fassbender-scitt-time-anchor`) son individuales, no estándares | Bajo | **No** (herramienta + flujo fuera de `qce/`) |
| R2 | **Aprobaciones k-de-n** (varias firmas independientes para registrar una identidad o aprobar un release) y, a medio plazo, **ML-DSA umbral** | «Un agente con permiso de escritura podría registrar su propia clave» (T11) | k-de-n con las firmas actuales: sin riesgo nuevo. Umbral: **investigación** (Mithril, Quorus —USENIX Security 2026—, convocatoria de umbrales de NIST); Quorus afirma firmas verificables con ML-DSA estándar **[PROBABLE]** | k-de-n: medio. Umbral: no implementar aún | k-de-n: **sí** |
| R3 | **Combinador estandarizado: ETSI TS 103 744 v1.2.1** (CatKDF y CasKDF; hay una norma de intercambio híbrido *autenticado* en desarrollo con QKD opcional) | QCE1 y QIL1 son «composiciones propias sin revisar»; la mezcla clave QKD + PQC «no ha sido revisada» | **[PROBABLE]**: versión 1.2.1 de marzo de 2025; leer el PDF primario de ETSI antes de decidir | Medio | **Sí** |
| R4 | **HPKE poscuántico** (`draft-ietf-hpke-pq-04`, ruta de estándares) y **X-Wing** (`draft-connolly-cfrg-xwing-kem-11`) para «cifrar hacia una clave pública» | No hay forma estándar de exportar o respaldar el almacén de claves hacia un destinatario poscuántico | **[PROBABLE]** borradores | Medio | **Sí** (si va en `qce/key_management`) |
| R5 | **Perfil «CNSA 2.0 puro»**: ML-KEM-1024 sin híbrido (`draft-ietf-tls-mlkem-11`, informativo) + ML-DSA-87 + AES-256 | LIMITATIONS: el nivel ALTO «no hace conforme con CNSA 2.0» porque el híbrido lleva X25519 | **[PROBABLE]**; confirmar que OpenSSL 3.5 ofrece el grupo ML-KEM puro en TLS **[NO VERIFICADO]** | Bajo–medio | **Sí** (política) |
| R6 | **Firmas hash con estado (LMS/XMSS, SP 800-208)** para firmar releases o anclas | Diversidad de supuestos: solo dependemos de retículos y curvas; nuestro almacén ya lleva `epoch` y ciclo de vida | **[PROBABLE]** (blogs de proveedores; la aprobación de NSA solo para LMS/XMSS **[NO VERIFICADO]** en el documento original). Riesgo clave: **reutilizar el estado rompe la seguridad** | Medio–alto | **Sí** |
| R7 | **AuthKEM / KEMTLS** (`draft-celi-wiggers-tls-authkem-07`, informativo): autenticar con KEM en lugar de firmas para reducir el tamaño del apretón | La brecha B1 (autenticación TLS no poscuántica) y el tamaño de las firmas ML-DSA | **Experimental**; no confirmé que haya implementación en OpenSSL **[HIPÓTESIS]** | Alto | **Sí** |
| R8 | **IPsec/IKEv2 con ML-KEM y claves QKD como PSK**: RFC 9370 (varios intercambios de claves), `draft-ietf-ipsecme-ikev2-mlkem`, y RFC 9867 para mezclar claves precompartidas (mejora a RFC 8784) | Hoy el producto solo cubre TLS y QCE1; IPsec ampliaría el alcance de QKD | **[PROBABLE]** borradores/RFC indexados; nada leído en primario | Alto (depende de strongSwan u otro) | Probablemente fuera de `qce/` |
| R9 | **Fuentes de entropía cuánticas validadas (SP 800-90B / ESV)** mezcladas **con** `os.urandom`, nunca en su lugar | El simulador QKD usa `os.urandom`; no hay interfaz de entropía enchufable | **[PROBABLE, declarado por proveedores]**: ID Quantique, QuintessenceLabs, Quantinuum; verificar en la base del CMVP | Medio, y **sin hardware** no se puede probar | **Sí** |
| R10 | **GS QKD 004 y 020 de ETSI** (otras interfaces de entrega de claves) | Solo tenemos el adaptador 014 | **[NO VERIFICADO]**: solo vi una referencia en un resumen de 2026 | Medio | Probablemente fuera de `qce/` |

## 2. Rutas que miré y **no** recomiendo ahora
- **Pruebas de conocimiento nulo poscuánticas** (STARK, retículos): las pruebas siguen siendo mucho mayores que las clásicas (una fuente habla de ~1.000×) y no resuelven ninguna brecha nuestra.
- **PAKE poscuántico** (`draft-vos-cfrg-pqpake-02`, Apple/UC Irvine): solo aplica si el producto tuviera inicio de sesión con contraseña; no lo tiene.
- **Merkle Tree Certificates:** ya en la comparativa; ayuda a escala web, no a un laboratorio.
- **Cadenas de re-claveo continuo (Triple Ratchet de Signal):** útil solo si el producto crece hacia mensajería.
- **No cubierto por mi búsqueda:** reparto de secretos poscuántico para custodia, MLS con suites PQ y QKD con RFC 8784. Quedan pendientes de investigar.

## 3. Tres caminos y recomendación

- **A. Confianza verificable primero: R1 y, después, R2 (k-de-n).** R1 se hace **sin tocar `qce/`** y cierra una limitación que ya declaramos. Es lo de mayor retorno por esfuerzo.
- **B. Estandarizar la composición: R3, R4 y R5.** Reducen la superficie «propia sin revisar», pero cambian `qce/` y deben ir en el paquete único de la Fase 2 con lo que diga el revisor. Antes, leer el PDF de ETSI TS 103 744 (gratuito) y mapearlo a QCE1.
- **C. Ampliar alcance: R6, R8, R9, R10.** Más trabajo y, en parte, sin hardware para probar; esperar a tener tracción o un socio de laboratorio.

**Recomiendo A ahora, B con el revisor, C después.** Una vez hecho R1, la siguiente decisión barata es **leer el documento primario de R3** (ETSI), porque podría cambiar la forma de QCE1 y conviene saberlo antes de la revisión humana.

## 4. Fuentes (secundarias salvo indicación)
- [ETSI TS 103 744 v1.2.1](https://standards.iteh.ai/catalog/standards/etsi/02c4df1f-ba7f-43c8-95ce-b333e40e8a71/etsi-ts-103-744-v1-2-1-2025-03) · [resumen de la actualización](https://postquantum.com/quantum-policy/etsi-hybrid-key-establishment/) · [PDF de la v1.1.1 en ETSI](https://www.etsi.org/deliver/etsi_ts/103700_103799/103744/01.01.01_60/ts_103744v010101p.pdf)
- [Quorus: ML-DSA umbral (USENIX Security 2026)](https://www.usenix.org/conference/usenixsecurity26/presentation/bienstock) · [Mithril](https://csrc.nist.gov/csrc/media/Projects/threshold-cryptography/documents/TCall-1/Mithril-PW01.pdf) · [MPTS 2026](https://csrc.nist.gov/Events/2026/mpts2026)
- [AuthKEM](https://ftp.sjtu.edu.cn/pub/internet-drafts/draft-celi-wiggers-tls-authkem-07.xml) · [draft-ietf-tls-mlkem-11](https://www.ietf.org/archive/id/draft-ietf-tls-mlkem-11.html) · [HPKE PQ](https://www.ietf.org/archive/id/draft-ietf-hpke-pq-04.html) · [X-Wing -11](https://www.ietf.org/archive/id/draft-connolly-cfrg-xwing-kem-11.html)
- [Rekor v2](https://blog.sigstore.dev/rekor-v2-alpha/) · [anclaje temporal (borrador)](https://datatracker.ietf.org/doc/draft-fassbender-scitt-time-anchor/)
- [LMS/XMSS y CNSA 2.0 (wolfSSL)](https://wolfssl.com/?p=43057) · [IKEv2 + ML-KEM](https://www.ietf.org/archive/id/draft-ietf-ipsecme-ikev2-mlkem-09.xml) · [CPaceOQUAKE+](https://ftp.kaist.ac.kr/ietf/draft-vos-cfrg-pqpake-02.txt)
- [ID Quantique: QRNG y NIST](https://www.idquantique.com/qrng-chip-nist-certification/) · [QuintessenceLabs: validación SP 800-90B](https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents/entropy/E145_PublicUse.pdf)
