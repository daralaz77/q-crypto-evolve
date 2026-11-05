# Seguridad / Security policy

**Este es un laboratorio, no un producto.** No lo uses para proteger datos reales. Lee `LIMITATIONS.md` y `THREAT_MODEL.md`: allí están, medidos, los límites conocidos (sin revisión humana externa, QKD simulado, HSM probado solo con SoftHSM, sin FIPS 140-3).
*This is a research lab, not a product. Do not use it to protect real data.*

## Cómo reportar una vulnerabilidad / How to report
- **Canal principal:** el **reporte privado de vulnerabilidades de GitHub**: <https://github.com/daralaz77/q-crypto-evolve/security/advisories/new> (pestaña *Security → Report a vulnerability*). No abras una *issue* pública con detalles explotables.
- **Alternativa** si no puedes usar GitHub: escribe a `director@daralaz.com` con el asunto «Q-Crypto Evolve: seguridad». No hay clave PGP publicada: **no envíes por correo detalles explotables completos**; manda un resumen y pide que abramos un canal privado en GitHub.
- *Use GitHub's private vulnerability reporting (link above). Fallback: `director@daralaz.com` — there is no PGP key, so send only a short summary by email and ask for a private GitHub channel. Please do not open a public issue with exploit details.*

## Qué debe traer un reporte / What to include
- Qué componente o archivo y qué versión (el `release_id` o el *commit*).
- El impacto que crees que tiene y bajo qué modelo de amenaza (`THREAT_MODEL.md`).
- Pasos para reproducirlo o una prueba de concepto; si puedes, la causa raíz.
- Si ya lo conoce alguien más o tienes una fecha límite de divulgación.

## Qué esperar
- Es un proyecto de **una sola persona mantenedora**, sin equipo ni acuerdos de nivel de servicio. Estos plazos son **objetivos de mejor esfuerzo, no garantías**:
  - **Acuse de recibo:** en 7 días.
  - **Primera evaluación** (¿se reproduce? ¿qué gravedad?): en 14 días.
  - **Corrección o mitigación** de lo confirmado: según la gravedad; te iremos informando del estado.
  - **Divulgación coordinada:** pedimos 90 días desde el acuse antes de publicar los detalles, o hasta que haya corrección, lo que ocurra primero. Si hay explotación activa, lo hablamos.
- Lo que se confirme se registrará en `learning/incidents.jsonl` (libro de incidentes encadenado por hash) con una prueba de reproducción, y se corregirá con una prueba de regresión permanente. El procedimiento completo está en [`docs/RESPUESTA_A_INCIDENTES.md`](docs/RESPUESTA_A_INCIDENTES.md).
- Para lo confirmado de gravedad **media o superior (CVSS)** publicaremos un aviso de seguridad de GitHub (*GitHub Security Advisory*) y pediremos CVE, y te daremos el crédito que prefieras (o ninguno).
- **No hay programa de recompensas (*bug bounty*)**: no podemos pagar hallazgos. Lo único que ofrecemos es crédito público y una respuesta seria.
- Si encuentras un fallo **en el método de verificación** (las puertas, la mutación, la ceremonia de firmas), también nos interesa: es parte del alcance.

## Investigación de buena fe / Good-faith research
Si buscas vulnerabilidades en este repositorio **de buena fe** —sin acceder a datos de terceros, sin degradar servicios de otros y sin extorsión— no emprenderemos acciones legales contra ti por esa investigación, y pedimos a cambio que no divulgues los detalles antes del plazo acordado. Esto no cubre sistemas que no son nuestros (GitHub, tu proveedor, etc.), que tienen sus propias reglas. *We will not pursue legal action over good-faith research within this repository; please respect the disclosure timeline.*

## Versiones con soporte / Supported versions
Solo la rama `main` (último *commit* con las puertas G1–G4 en verde). No hay versiones antiguas con parches. *Only `main` is supported.*

## Alcance
Dentro: `qce/`, `tests/`, los modelos formales (`formal/`), la especificación (`docs/QCE1_SPEC.md`, `docs/QKD_LAYER_SPEC.md`) y el kit de la nube (`docs/hsm_cloud/`, sin probar). También los flujos de CI (`.github/workflows/`) y la cadena de suministro (`requirements*.txt`, `sbom.cdx.json`).
Fuera: OpenSSL, NSS, GnuTLS, SoftHSM y demás herramientas de terceros (repórtalas a sus proyectos).

## Alertas de secretos esperadas (falsos positivos) / Expected secret-scanning alerts
Las pruebas de los escáneres de secretos (`tests/test_tooling.py`, `tests/test_keys_qkd_log.py` y sus copias en `releases/*/src/tests/`) contienen **cadenas falsas a propósito** (por ejemplo una `API_KEY` que empieza por `sk_live_` con relleno repetido, `password=hunter2` y una clave privada PEM de relleno `AAA`) para comprobar que los escáneres las detectan. No son credenciales reales. Cualquier alerta de GitHub sobre esos archivos se cierra como «usada en pruebas». *These are intentional fake strings used to test our own scanners, not real credentials.*
