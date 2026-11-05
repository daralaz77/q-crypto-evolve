# Respuesta a incidentes y vulnerabilidades

Procedimiento escrito del proyecto, basado en el capítulo «Internal Vulnerability Response Policies» de la [guía de buenas prácticas de OSTIF](https://github.com/ostif-org/best-practices-guide) y en lo que el repositorio **ya implementa**: el libro de incidentes encadenado por hash (`learning/incidents.jsonl`), las puertas G1–G6 y la reversión verificada. Cómo reportar: ver [`SECURITY.md`](../SECURITY.md).

**Quién responde:** la persona mantenedora (hoy, una sola). Es un proyecto de laboratorio sin acuerdo de nivel de servicio; los plazos son objetivos de mejor esfuerzo. **Quién revisa:** nadie de forma independiente todavía (G5 pendiente); por eso el estado público es `REVIEW_REQUIRED`.

## A. Un reporte de vulnerabilidad (de fuera o de dentro)

| Paso | Qué se hace | Dónde queda constancia |
|---|---|---|
| 1. Recibir | El reporte llega por el aviso privado de GitHub (o por correo). No se discute en público. | El propio aviso de seguridad |
| 2. Acusar recibo | Respuesta a quien reporta con el plazo esperado y el siguiente paso (objetivo: 7 días). | El aviso |
| 3. Registrar | Se abre el incidente con `Ledger.open(Incident(...))`: módulo, síntoma, gravedad (`baja`/`media`/`alta`/`critica`), estado `abierto`. | `learning/incidents.jsonl` (cadena de hashes: no se puede reescribir sin que G1 lo detecte) |
| 4. Triaje | Reproducir y confirmar (estado `reproducido`, certeza `CONFIRMADA`/`PROBABLE`), medir el impacto y priorizar. Un incidente grave sin resolver **bloquea** G4. Objetivo: 14 días. | Mismo registro + comentario en el aviso |
| 5. Planificar la corrección | Nivel de reparación 1 (automática), 2 (exige revisión) o 3 (bloqueada hasta autorización humana). Es nivel 2 lo que toque `qce/pqc/`, `qce/protocols/`, `qce/key_management/`, `qce/symmetric/` y similares; es nivel 3 (bloqueado hasta autorización humana) lo que toque `gates.json`, `qce/core/chainlog.py`, `qce/security/scanners.py` o `learning/` (véase `change_level`). | Campo `repair_level` |
| 6. Corregir | Mínima y aislada, **con una prueba de regresión permanente** (sin prueba, el incidente no puede pasar a `resuelto`). | `reproduction_test` |
| 7. Verificar | `python -m qce gates` completo: G1–G4 en verde sobre el nuevo `release_id`; pedir a quien reportó que confirme la corrección. | `benchmarks/gates_latest.json` |
| 8. Comunicar | Aviso de seguridad de GitHub y CVE para gravedad **media o superior**; avisar a usuarios y proyectos relacionados si les afecta (OpenSSL, NSS, etc., si el fallo está en su lado: se les reporta a ellos). | Aviso publicado y nota en la versión |
| 9. Cerrar y aprender | Incidente `resuelto`, lección en el registro (`PROPOSED` → `CONFIRMED` tras revisión). Si el fallo estaba en el método de verificación, se añade un mutante o una puerta nueva. | `lesson` / `lesson_state` |

Divulgación coordinada: se pide a quien reporta 90 días desde el acuse (o hasta que haya corrección). Si hay explotación activa se acorta de común acuerdo.

## B. Un incidente de cadena de suministro o de seguridad propio

Ejemplos: una dependencia o una *acción* de GitHub comprometida, una clave de firma o un token filtrados, un envío malicioso al repositorio, un secreto subido por error.

1. **Contener:** revocar/rotar lo comprometido de inmediato (token, clave, acceso). Si es una clave de firma de la ceremonia G5/G6: editar `trust/registry.json` para retirar la identidad y registrar una nueva con `python -m qce identity register`.
2. **Congelar:** no publicar nada hasta saber el alcance; si hay un *release* afectado, volver al último estable verificado con `rel.rollback` (restaura solo código y pruebas; **nunca** toca claves, contadores ni el libro de incidentes).
3. **Evaluar el alcance:** ¿qué versiones, qué archivos, qué datos? Comprobar los hashes de `requirements.hashes.txt` y de `requirements-ci-*.hashes.txt`, comparar el SBOM (`sbom.cdx.json`) y revisar el historial de Git.
4. **Registrar** el incidente igual que en el apartado A (pasos 3–4), con la causa raíz.
5. **Comunicar:** a quienes usen el proyecto y a los proyectos afectados; si la ley del país de la persona mantenedora lo exige, a la autoridad competente. Guías de referencia de organismos públicos: [CISA](https://www.cisa.gov/resources-tools/resources/cyber-incident-guide), [BSI](https://www.bsi.bund.de/EN/IT-Sicherheitsvorfall/Unternehmen/unternehmen.html), [SingCERT](https://www.csa.gov.sg/Tips-Resource/Resources/singcert/incident-response-checklist).
6. **Recuperar y endurecer:** reconstruir con dependencias verificadas, repetir las puertas, y añadir la prueba o el control que habría detectado el incidente.

## C. Qué se maneja internamente y qué se externaliza

- Vulnerabilidades en el código de Q-Crypto Evolve: **internamente** (este procedimiento).
- Fallos en OpenSSL, NSS, GnuTLS, SoftHSM, `cryptography`: se reportan **al proyecto responsable** y aquí se documenta el efecto y la mitigación. El puente TLS depende de OpenSSL ≥ 3.5: hay que **seguir sus avisos** (`openssl-announce`) y los de `pyca/cryptography`.
- Una auditoría externa (cuando exista) sigue el mismo procedimiento A para sus hallazgos, y el informe se publica.

## D. Límites honestos

- Una sola persona responde: no hay turnos ni cobertura 24/7.
- No hay revisión independiente todavía (G5): los incidentes corregidos los verifica el mismo mantenedor, ayudado por las puertas automáticas.
- Este documento es **un procedimiento escrito, no una certificación**: no se ha ejercitado con un reporte externo real.
