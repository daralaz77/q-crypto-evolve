# Seguridad / Security policy

**Este es un laboratorio, no un producto.** No lo uses para proteger datos reales. Lee `LIMITATIONS.md` y `THREAT_MODEL.md`: allí están, medidos, los límites conocidos (sin revisión humana externa, QKD simulado, HSM probado solo con SoftHSM, sin FIPS 140-3).
*This is a research lab, not a product. Do not use it to protect real data.*

## Cómo reportar una vulnerabilidad / How to report
- Usa el **reporte privado de vulnerabilidades de GitHub** (pestaña *Security → Report a vulnerability*) de este repositorio. No abras una *issue* pública con detalles explotables.
- *Use GitHub's private vulnerability reporting on this repository; please do not open a public issue with exploit details.*

## Qué esperar
- Es un proyecto sin equipo ni acuerdos de nivel de servicio: la respuesta es de mejor esfuerzo.
- Lo que se confirme se registrará en `learning/incidents.jsonl` (libro de incidentes encadenado por hash) con una prueba de reproducción, y se corregirá con una prueba de regresión permanente.
- Si encuentras un fallo **en el método de verificación** (las puertas, la mutación, la ceremonia de firmas), también nos interesa: es parte del alcance.

## Alcance
Dentro: `qce/`, `tests/`, los modelos formales (`formal/`), la especificación (`docs/QCE1_SPEC.md`, `docs/QKD_LAYER_SPEC.md`) y el kit de la nube (`docs/hsm_cloud/`, sin probar).
Fuera: OpenSSL, NSS, GnuTLS, SoftHSM y demás herramientas de terceros (repórtalas a sus proyectos).

## Alertas de secretos esperadas (falsos positivos) / Expected secret-scanning alerts
Las pruebas de los escáneres de secretos (`tests/test_tooling.py`, `tests/test_keys_qkd_log.py` y sus copias en `releases/*/src/tests/`) contienen **cadenas falsas a propósito** (por ejemplo una `API_KEY` que empieza por `sk_live_` con relleno repetido, `password=hunter2` y una clave privada PEM de relleno `AAA`) para comprobar que los escáneres las detectan. No son credenciales reales. Cualquier alerta de GitHub sobre esos archivos se cierra como «usada en pruebas». *These are intentional fake strings used to test our own scanners, not real credentials.*
