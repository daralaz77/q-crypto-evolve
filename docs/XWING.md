# X-Wing (KEM híbrido X25519 + ML-KEM-768) — módulo autónomo

**Código:** `qce/pqc/xwing.py` · **Pruebas:** `tests/test_xwing.py` (vectores en `tests/vectors/xwing_draft11.json`) · **Mutantes:** `qce/evolve/mutants/pqc_xwing.py`
**Especificación seguida:** [draft-connolly-cfrg-xwing-kem-11](https://datatracker.ietf.org/doc/html/draft-connolly-cfrg-xwing-kem-11) (IETF CFRG, informativo). **No es un RFC y puede cambiar.**

## Qué es y qué NO es
- Es una primitiva **autónoma**: genera claves a partir de una semilla de 32 bytes, encapsula y desencapsula. **No está conectada al apretón QCE1 ni a ninguna suite.**
- **No sustituye** al KEM híbrido de `qce/pqc/hybrid.py`, que sigue siendo el que usa QCE1. Conectar X-Wing al protocolo cambiaría el formato de los mensajes y obligaría a actualizar
  la especificación, el modelo formal (Tamarin) y la conformidad; esa decisión queda aparte.
- Está escrito por una instancia de Claude y **no ha sido revisado por ninguna persona**.

## Diferencias con el híbrido propio (no mezclar)
| | `hybrid.py` (QCE1) | `xwing.py` |
|---|---|---|
| Orden en clave pública y texto cifrado | X25519 ‖ ML-KEM | **ML-KEM ‖ X25519** |
| Combinador | HKDF-SHA256 sobre ss_M ‖ ss_X, con sal = etiqueta ‖ **todo el texto cifrado** ‖ clave pública | SHA3-256(ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ etiqueta); **no incluye ct_M ni pk_M** (se apoya en que ML-KEM es IND-CCA) |
| Clave privada | semilla de 96 bytes (X25519 32 + ML-KEM 64) | semilla de **32 bytes**, expandida con SHAKE256 a 96 |
| Longitud de clave pública / texto cifrado | 1216 / 1120 bytes | 1216 / 1120 bytes (**misma longitud, otro formato**) |

## Qué se ha comprobado
- **Vectores del borrador (Apéndice C, 3 vectores):** la clave pública derivada de la semilla coincide, y desencapsular el texto cifrado del borrador da el secreto publicado. Eso ejercita ML-KEM, X25519 y el combinador.
- **Lo que NO se reproduce:** la encapsulación del vector (`eseed`), porque `cryptography` no permite fijar la aleatoriedad de ML-KEM. La encapsulación se prueba con ida y vuelta y con una recomputación independiente solo con las primitivas.
- Entradas inválidas: longitudes incorrectas, clave ML-KEM fuera de rango, punto X25519 de orden pequeño y uso tras `destroy` fallan cerradas.
- Pruebas de mutación: cada control tiene su mutante (ver arriba).
- Los autores del borrador marcan el Apéndice C como TODO (los vectores pueden cambiar): si se publica una versión nueva, hay que volver a comprobar.

## Desviación y límites declarados
- La decapsulación **falla cerrada** ante un punto X25519 de orden pequeño (`AuthenticationFailure`); el borrador no lo exige.
- El borrado de la clave es de **mejor esfuerzo** en Python (`LIMITATIONS.md`).
- No cubre canales laterales (Python no es de tiempo constante).
- Que X-Wing tenga análisis público no significa que **esta implementación** esté auditada.

## Si se quisiera conectar a QCE1 (no hecho)
Haría falta: una suite nueva en la política, cambio de `session.py`, actualizar `docs/QCE1_SPEC.md` (formatos, tabla de constantes), el modelo `formal/qce1.spthy` y su conformidad, un ADR, y repetir puertas y firma G6.
