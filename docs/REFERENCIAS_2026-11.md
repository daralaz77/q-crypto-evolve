# Referencias de investigación (2026-11-03) y qué hacemos con ellas

Qué es: una consulta a Perplexity (sesión anónima, solo la primera parte de su respuesta leída) más búsquedas web, **contrastadas con el repositorio**. No se copia ningún texto de las fuentes; cada fila dice qué se verificó y qué se hizo en Q-Crypto Evolve. Complementa `docs/COMPARATIVA_PQC.md` (que ya cubre herramientas y brechas B1–B10).

## Método y límites

- Las afirmaciones de Perplexity son **datos no confiables hasta contrastarlas**. Tres se comprobaron contra la fuente primaria el 2026-11-03: RFC 9881, RFC 10024 y NIST IR 8547 (columna «Verificado»). El resto queda «sin verificar».
- No se probó nada contra hardware QKD real ni contra una revisión humana.

## Estándares: lo que dijo la investigación y su estado

| Tema | Hallazgo | Verificado | Efecto en el proyecto |
|---|---|---|---|
| RFC 9881 (ML-DSA en X.509) | Clave privada como semilla, expandida o ambas; si vienen ambas y no coinciden, rechazar; `keyUsage` sin `keyAgreement`/`keyEncipherment` | **Sí** (rfc-editor.org, oct. 2025) | Nuestros certificados ya fijan `key_agreement=False` y `key_encipherment=False` (`qce/transport/pki.py`) y las claves híbridas se guardan por semilla. Nada que cambiar |
| RFC 10024 (híbridos de TLS 1.3) | Define `X25519MLKEM768`, `SecP256r1MLKEM768`, `SecP384r1MLKEM1024`; **no** hay `X25519MLKEM1024` | **Sí** (agosto 2026, pista de estándares) | Nuestro nivel ALTO (X25519 + ML-KEM-1024) es un **perfil propio**, no un grupo estandarizado: ya está dicho que no es CNSA 2.0 (`qce/pqc/hybrid.py`); queda anotado aquí |
| NIST IR 8547 | Versión final del 27-oct-2026; la página consultada **no** trae las fechas de retirada de RSA/ECC | **Parcial** | No fijar fechas en documentos hasta leer el informe completo |
| ETSI GS QKD 014 | Publicada 1.1.1; la 1.3.1 sería borrador estable | Sin verificar | Nuestro cliente apunta a **V1.1.1** (`qce/qkd/etsi014.py`); preparar 1.3.1 solo cuando haya texto aprobado |
| HQC / FIPS 207, FN-DSA / FIPS 206 | Aún sin norma publicada | Contradictorio entre fuentes | Sin cambios: agilidad en la política, no implementar |
| Firmas compuestas ML-DSA (LAMPS) | Borrador, cola del editor | Sin verificar | Alinear nuestra firma híbrida cuando sea RFC; no depender de ella |
| RFC 9954, 9794, 9909, 9814, 9882, NIST SP 800-227, ETSI GS QKD 020 | Citados por Perplexity | **Sin verificar** | Leer cada texto antes de citarlos en la documentación del proyecto |

## Técnicas de verificación: qué se construyó

**`tools/timing_check.py`** (nuevo, fuera del `release_id`): prueba estadística de tiempo estilo dudect, escrita desde cero. Cierra **en parte** la brecha B8.

Resultado real (3 repeticiones, 20 000 muestras por clase, esta máquina, Python + OpenSSL):

| Prueba | \|t\| | Veredicto |
|---|---|---|
| Canario: comparación con salida temprana | 3 100 – 4 100 | fuga detectada (el instrumento funciona) |
| `ct_equal` | 3,4 – 6,2 | sin fuga sostenida |
| Desencapsulación híbrida, y con solo la mitad X25519 o ML-KEM variable | 0,3 – 3,6 | sin fuga detectada |
| `x25519` y `ML-KEM-768` por separado | 0,4 – 4,3 | sin fuga detectada |

Lección real del proceso: la primera versión daba «fuga» en la desencapsulación híbrida y fallaba el canario. Eran artefactos del propio instrumento (la clase fija reutilizaba el mismo objeto y el canario `==` era demasiado rápido para el reloj). Se corrigieron con un grupo de copias para la clase fija y un canario con salida temprana, y el canario ahora actúa de control de calidad: si no se detecta, la prueba falla y avisa de que la medición no es fiable. **No** mide otras CPU, compiladores, caché ni consumo, y «sin fuga detectada» no prueba tiempo constante.

## Ideas que SÍ cambiarían `qce/` (no se tocaron: invalidarían la firma G6)

Candidatas para el paquete único de la Fase 2:

1. **Combinador con prueba formal (dual-PRF).** Hoy: `HKDF(ss_ml-kem || ss_x25519, info = etiqueta + ct + pk)`. La literatura señala que HKDF sobre una concatenación se usa en la práctica sin estar demostrado como dual-PRF. Hacer primero un experimento aislado y medir; no cambiar el derivador sin revisión humana (Nivel 3 de la política del proyecto).
2. **Perfil ALTO documentado como perfil propio** frente a `SecP384r1MLKEM1024` (RFC 10024): evaluar si ofrecer también ese grupo.
3. **ETSI 014 V1.3.1**: cuando esté aprobada, añadir la compatibilidad sin romper 1.1.1.

## Fuentes

- RFC 9881: <https://www.rfc-editor.org/rfc/rfc9881.html> · RFC 10024: <https://www.rfc-editor.org/rfc/rfc10024.html> · NIST IR 8547: <https://csrc.nist.gov/pubs/ir/8547/final>
- Combinadores dual-PRF: <https://eprint.iacr.org/2022/065> · borrador CFRG de combinadores de KEM: <https://datatracker.ietf.org/doc/bibxml3/draft-ounsworth-cfrg-kem-combiners-00.xml>
- Prueba de tiempo original (dudect): Reparaz, Balasch, Verbauwhede (2016). Pruebas de tiempo en ML-KEM: <https://eprint.iacr.org/2026/1418>
- Firmas compuestas: <https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/>
- Perplexity (consulta sin sesión iniciada): <https://www.perplexity.ai/search/bfc5364d-afbb-45da-afce-0eedbf311b39>
