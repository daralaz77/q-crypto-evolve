# Comparativa de herramientas de criptografía poscuántica y brechas de Q-Crypto Evolve

Fecha de la investigación: 2026-10-29. Alcance: bibliotecas, protocolos, estándares y automatización; qué falta a este laboratorio **además de lo ya declarado** en `LIMITATIONS.md` (revisión humana G5, KME real, HSM real, FIPS).

## Método y límites (léelo primero)

- Búsqueda web en una sola sesión. Verifiqué **en la página primaria** solo RFC 10024 (rfc-editor.org) y la página de FIPS de OpenSSL (openssl-library.org). Todo lo demás viene de fuentes secundarias (blogs, resúmenes, listas de correo) y **no está confirmado** contra el documento original; está marcado.
- Etiquetas: **[CONFIRMADA]** = lo vi en una fuente primaria o en nuestro repositorio; **[PROBABLE]** = fuentes secundarias coherentes entre sí; **[HIPÓTESIS]** = razonamiento mío o dato contradictorio; **[NO VERIFICADO]** = la búsqueda no lo cubrió.
- No hay medición propia de rendimiento ni de seguridad de ninguna herramienta ajena. Nada de esto es una recomendación comercial.

## 1. Comparativa de herramientas

| Herramienta | Qué ofrece | Estado verificable | Qué podemos adaptar |
|---|---|---|---|
| **OpenSSL 3.5 (LTS, hasta abr. 2030) / 4.0** | ML-KEM, ML-DSA, SLH-DSA en el proveedor por defecto; grupo híbrido `X25519MLKEM768` por defecto [PROBABLE]. 4.0 añade ML-DSA-MU y endurece X.509 [PROBABLE]; 4.1 en alfa optimiza ML-DSA/ML-KEM [PROBABLE] | **[CONFIRMADA]** el certificado FIPS 140-3 n.º 4985 es del módulo 3.1.2 (sin evidencia de PQC); **3.5.8 está «en revisión del CMVP»** sin certificado | Ya la usamos (puente `ctypes`). Mantener 3.5 LTS; vigilar 4.x |
| **AWS-LC** (Amazon) | «Primera biblioteca con ML-KEM en una validación FIPS 140-3» (AWS-LC FIPS 3.0), ML-KEM-512/768/1024 | [PROBABLE] por resúmenes de AWS; el alcance exacto debe leerse en el certificado del CMVP (un certificado solo cubre lo que lista) | Candidata a **segunda implementación** para pruebas diferenciales y vía hacia FIPS |
| **liboqs / oqs-provider** (Open Quantum Safe, PQCA) | Biblioteca de prototipos; 0.16.0 (9-jul-2026) retiró SPHINCS+ y actualizó mlkem-native a 1.2.0 [PROBABLE]; ML-KEM por defecto = mlkem-native desde 0.13 [PROBABLE] | Activo. Sobre oqs-provider: un hilo de NIST sugiere que el repositorio actual ya no registra los algoritmos PQC; **sin confirmar** [NO VERIFICADO] | Fuente de una **segunda implementación** de KEM/firmas para diferencial; no para producción (es una biblioteca de prototipado) |
| **mlkem-native** (PQCA) | ML-KEM en C; C comprobado con CBMC (memoria/enteros); ensamblador AArch64/x86_64 con prueba de tiempo constante en HOL Light [PROBABLE] | Verificación formal declarada por el proyecto; no la reproduje | Segunda implementación verificada para contrastar con OpenSSL |
| **libcrux** (Cryspen, Rust) | ML-KEM verificado con hax y F*; **encontraron un fallo de tiempo con su marco de verificación** [PROBABLE]; algunos listados dicen que las rutas SIMD no están verificadas [PROBABLE] | Parcial | Referencia de método: verificación como parte del flujo |
| **Go `crypto/mlkem`** | ML-KEM en la biblioteca estándar; usa vectores Wycheproof | [PROBABLE] por un commit público | Modelo: probar con vectores de **casos límite y negativos** |
| **Bouncy Castle, wolfSSL, PQClean** | — | **[NO VERIFICADO]** (la búsqueda no los cubrió) | Investigar antes de citar |
| **Google Cloud KMS / AWS KMS** | ML-DSA y SLH-DSA disponibles; ML-KEM y el híbrido X-Wing en vista previa en Google; AWS KMS con ML-DSA [PROBABLE] | Los estados cambian rápido: leer las notas de versión vigentes | Nuestro kit `docs/hsm_cloud/` solo probó RSA-PSS con SoftHSM: probar **ML-DSA en un KMS real** |
| **HSM (Thales, Entrust, Utimaco)** | Dicen tener ML-KEM/ML-DSA con CAVP; SLH-DSA desigual [HIPÓTESIS: dato de una consultora]. PKCS#11 3.2 trae ML-DSA/SLH-DSA/ML-KEM [PROBABLE] | Sin ficha de fabricante verificada | Probar la ruta PKCS#11 con un token que soporte PQC |
| **Q-Crypto Evolve** | Ver §3 | **[CONFIRMADA]** en este repositorio | — |

## 2. Protocolos y estándares

| Tema | Estado (al 2026-10-29) | Relevancia para nosotros |
|---|---|---|
| **RFC 10024**, híbridos PQ/T para TLS 1.3 | **[CONFIRMADA]** Standards Track; define `X25519MLKEM768` (0x11EC), `SecP256r1MLKEM768` (0x11EB) y `SecP384r1MLKEM1024` (0x11ED); autores de PQShield, AWS, Cloudflare y Waterloo | Ya usamos dos de los tres grupos. Falta `SecP256r1MLKEM768` (opción FIPS-friendly) |
| **FIPS 203/204/205** | [PROBABLE] finales desde agosto de 2024 | Los usamos (ML-KEM, ML-DSA, SLH-DSA) |
| **FN-DSA (FIPS 206)** y **HQC (FIPS 207)** | Contradictorio: una fuente dice que FIPS 206 está en aprobación; otra, con fecha 30-sep-2026, que **no hay borrador público** de ninguno [HIPÓTESIS: tratar como pendientes] | Preparar agilidad criptográfica; no implementar aún |
| **Firmas compuestas ML-DSA para X.509** (`draft-ietf-lamps-pq-composite-sigs`) | [PROBABLE] revisión 19, 14-oct-2026, aún borrador | Nuestra firma híbrida es propia («AND» de Ed25519 y ML-DSA); conviene **alinearla** cuando haya RFC |
| **ML-KEM en X.509** | [PROBABLE] RFC 9935 (marzo de 2026) | Útil si certificamos claves KEM |
| **X-Wing** (KEM híbrido X25519+ML-KEM-768) | [PROBABLE] borrador informativo `-10` (marzo de 2026), caducaba el 3-sep-2026 salvo renovación; sin RFC | Alternativa estándar a nuestro combinador propio (QCE1) |
| **Merkle Tree Certificates** (Cloudflare/Google) | [PROBABLE] experimento con ~1.000 certificados; Chrome dice que no planea aceptar certificados PQ clásicos en su almacén raíz | Resuelve el tamaño de las firmas ML-DSA (≈14,7 kB → ≈0,7 kB) a escala web; **marginal** para un laboratorio |
| **Signal SPQR / Triple Ratchet; Apple PQ3** | [PROBABLE] ML-KEM-768 junto al Double Ratchet; PQ3 refresca la parte PQ cada ~50 mensajes y SPQR de forma continua | Referencia para **re-claveo continuo** si el producto crece hacia mensajería |
| **OpenSSH `mlkem768x25519`; Rosenpass / PQ-WireGuard** | [PROBABLE] SSH lo negocia por defecto; Rosenpass solo tiene análisis **simbólico** con ProVerif; un trabajo de USENIX Security 2025 halló debilidades en PQ-WireGuard y las corrigió | Confirma que **varias herramientas formales** encuentran lo que una sola no |
| **Plazos** | NIST IR 8547 (2030/2035), CNSA 2.0 (2030–2033), una orden de junio de 2026: **fuentes que se contradicen** [HIPÓTESIS] | No fijar fechas en documentos hasta leer los textos oficiales |

## 3. Dónde estamos (hechos del repositorio)

- **[CONFIRMADA]** Primitivas: ML-KEM-768/1024 y ML-DSA-65/87 vía `cryptography`/OpenSSL; SLH-DSA vía `ctypes`; TLS 1.3 con PSK de QKD y `X25519MLKEM768`; ETSI GS QKD 014 contra un emulador; HSM por PKCS#11 solo con SoftHSM.
- **[CONFIRMADA]** Vectores: ACVP de keyGen y sigVer; **ningún Wycheproof/CCTV** (búsqueda en `tests/`, `qce/` y `docs/`); LIMITATIONS declara «no hay vectores de encapsulación».
- **[CONFIRMADA]** Los certificados del transporte TLS son **ECDSA P-256** (`qce/transport/pki.py`): hoy **solo el intercambio de claves es poscuántico; la autenticación del servidor no lo es**.
- **[CONFIRMADA]** SBOM CycloneDX **1.5** con 3 componentes; `docs/SUPPLY_CHAIN.md` admite «no hay firma del SBOM ni atestación de procedencia».
- **[CONFIRMADA]** Un solo respaldo para las primitivas (OpenSSL); la interoperabilidad con GnuTLS y NSS cubre el transporte, no la corrección de las primitivas.
- **[CONFIRMADA]** Verificación formal solo simbólica (Tamarin); sin segunda herramienta.

## 4. Brechas nuevas (fuera de lo ya declarado), por prioridad

| # | Brecha | Evidencia | Qué hacer | ¿Cambia `release_id`? |
|---|---|---|---|---|
| B1 | **La autenticación en TLS no es poscuántica** (ECDSA P-256) | Código; RFC 10024 solo cubre el intercambio | Probar certificados **ML-DSA** con OpenSSL 3.5 (una guía de Red Hat dice que solo con CA local o autofirmados) y medir el aumento de tamaño del apretón | Sí (`qce/transport`), salvo que se pruebe en un directorio aparte |
| B2 | **Faltan vectores de encapsulación/desencapsulación y de casos límite** | LIMITATIONS + búsqueda sin resultados | Ejecutar los vectores **CCTV/Wycheproof** de ML-KEM (claves de encapsulación inválidas, rechazo implícito, casos «con mala suerte») | Sí si van en `tests/`; no si van en una carpeta aparte |
| B3 | **Sin pruebas diferenciales entre implementaciones** | Una sola implementación de las primitivas | Comparar OpenSSL contra mlkem-native o liboqs (y AWS-LC) con entradas aleatorias y de borde: mismas salidas | Carpeta aparte: no |
| B4 | **Inventario criptográfico (CBOM)** | SBOM 1.5; CycloneDX 1.6 introdujo la CBOM [PROBABLE] | Generar automáticamente una CBOM (algoritmos, parámetros, protocolos, certificados) desde nuestra política y escaneo | No (herramienta aparte) |
| B5 | **Combinador propio (QCE1) frente a uno estándar** | X-Wing es borrador informativo, sin RFC | Evaluar sustituir o alinear la mezcla de claves; reduce superficie sin revisar | Sí |
| B6 | **Sin atestaciones de procedencia ni análisis estático de flujos de trabajo** | `SUPPLY_CHAIN.md` | Atestaciones de artefactos de GitHub (SLSA), OpenSSF Scorecard, CodeQL, `zizmor` sobre los flujos [HIPÓTESIS: herramientas conocidas, no verificadas hoy] | No |
| B7 | **Una sola herramienta formal** | PQ-WireGuard: varias herramientas hallaron fallos | Traducir QCE1 a SAPIC+ para ProVerif/DEEPSEC además de Tamarin; mirar CryptoVerif para lo computacional | No |
| B8 | **Sin evidencia de tiempo constante propia** | KyberSlash: el fallo estaba en el compilador+código, no en el algoritmo [PROBABLE] | Fijar versiones de las bibliotecas, vigilar avisos, y una prueba tipo dudect de las comparaciones y del puente | Depende |
| B9 | **PQC real en HSM/KMS sin probar** | Solo RSA-PSS en SoftHSM | Probar ML-DSA en un KMS (Google/AWS) con el kit existente | No |
| B10 | **Agilidad para HQC y FN-DSA** | Pendientes en NIST | Mantener la política lista para añadirlos; no implementar antes de los estándares | — |

## 5. Tres rutas y recomendación

- **A. Evidencia primero (recomendada).** B2 + B3 + B4 + B6 en carpetas y flujos **fuera de `qce/` y `tests/`**: no invalidan tu firma de G6 y suben la confianza con datos nuevos e independientes. Esfuerzo bajo a medio.
- **B. Autenticación poscuántica en TLS.** B1 (y B9 después). Cambia código: va en el paquete único de la Fase 2 de `RUTA_ENDURECIMIENTO.md`, junto con lo que diga el revisor.
- **C. Alinearse con estándares.** B5 + B7 + firmas compuestas. Depende de que los borradores maduren; esperar.

Recomiendo **A ahora, B con el revisor, C cuando haya RFC**.

## 5b. Avance de la ruta A (2026-10-29)

| Brecha | Resultado real | Dónde |
|---|---|---|
| B2 vectores | **1.587 casos Wycheproof pasan** (ML-KEM-768/1024: ida y vuelta, rechazo implícito, longitudes malas, desbordamiento de módulo; ML-DSA-65/87: verificación con 451 firmas de borde). Sin fallos. Quedan sin ejecutar los de clave de desencapsulación expandida (la API no los importa) | `conformance/run_wycheproof.py` |
| B3 diferencial | 100 rondas (25 × ML-KEM-768/1024 y ML-DSA-65/87) entre OpenSSL 4.0.3 (embebido en `cryptography`) y 3.6.4 (CLI del sistema): **0 diferencias**. Es la misma familia de código; **no** es una implementación independiente | `conformance/differential.py` |
| B4 CBOM | CBOM CycloneDX 1.6 generada desde la política real (18 componentes); marca como vulnerables X25519, Ed25519 y la PKI ECDSA P-256 del transporte. **Sin validar contra el esquema oficial** | `tools/cbom.py`, `benchmarks/cbom.cdx.json` |
| B6 cadena de suministro | Flujo `security.yml`: CodeQL, Scorecard (sin publicar), zizmor y procedencia firmada del paquete (a demanda), con acciones fijadas por SHA | `.github/workflows/security.yml` |

Los canarios de `conformance/tests` comprueban que los ejecutores fallan si se altera un vector; así un verde no puede estar vacío.

## 6. Fuentes (secundarias salvo las dos primeras)

- [RFC 10024](https://www.rfc-editor.org/info/rfc10024/) (primaria) · [OpenSSL: CVEs y proveedor FIPS](https://openssl-library.org/news/fips-cve/) (primaria)
- [OpenSSL 3.5.4: envío a FIPS 140-3](https://openssl-library.org/post/2025-10-09-ossl3.5.4-fips-submission/) · [Cryspen: verificación de libcrux ML-KEM](https://cryspen.com/post/ml-kem-verification/) · [mlkem-native (AWS LibMLKEM)](https://github.com/awslabs/LibMLKEM)
- [liboqs 0.16.0](https://newreleases.io/project/github/open-quantum-safe/liboqs/release/0.16.0) · [PQCA TAC, feb. 2026](https://pqca.github.io/TAC/meeting-minutes/2026/2026-02-11-TAC.html)
- [Vectores ML-KEM (foro de NIST)](https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/aCAX-2QrUFw/m/hy5gwcESAAAJ) · [Go: pruebas Wycheproof](https://go.googlesource.com/go/+/0a9b01c5e1e5dd78cc40e15b795e51a356d0879d%5E%21/)
- [KyberSlash](https://kyberslash.cr.yp.to/papers.html) · [PQ-WireGuard, USENIX Security 2025](https://www.usenix.org/system/files/usenixsecurity25-lafourcade.pdf)
- [CBOM en CycloneDX](https://cyclonedx.org/capabilities/cbom/) · [X-Wing (borrador)](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/) · [firmas compuestas (borrador)](https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/)
- [Merkle Tree Certificates (Cloudflare)](https://blog.cloudflare.com/bootstrap-mtc/) · [Signal SPQR](https://cyberinsider.com/signal-adds-post-quantum-triple-ratchet-protocol-for-stronger-security/) · [SSTIC 2026: Triple Ratchet](https://www.sstic.org/2026/presentation/triple_ratchet/)
- [AWS: ML-KEM en AWS-LC FIPS](https://aws.amazon.com/security/post-quantum-cryptography/) · [Google Cloud KMS: KEM](https://cloud.google.com/blog/products/identity-security/announcing-quantum-safe-key-encapsulation-mechanisms-in-cloud-kms)
