# Notas del release v1.2 (borrador, sin publicar)

Estado: **laboratorio, sin auditoría externa.** Puertas G1–G4 en verde sobre el código de la ronda 8 (`release_id` 1ffd60f1065228b0): 1064 pruebas, 603 mutantes (597 puntuables, todos detectados; 5 equivalentes declarados), 35 incidentes históricos reproducidos y corregidos. **G5 (revisión independiente) sigue pendiente**, así que el estado es `REVIEW_REQUIRED`. La firma G6 de la persona que mantiene el proyecto se hace sobre un `release_id` concreto: este documento no la sustituye.

La versión del paquete (`pyproject.toml`) y la de la CLI no cambian con el release: «v1.2» es la etiqueta de la publicación.

## Qué cambia desde el release anterior (rondas 3 a 8)

| Ronda | Cambio | Dónde |
|---|---|---|
| 3 | Tres defectos corregidos y umbrales subidos | `THREAT_MODEL.md` |
| 4 | La clave QKD se RESERVA al recibir el ClientHello y se consume solo cuando el cliente demuestra poseerla (un ClientHello falso ya no la gasta); KME fijado por petición; `atomic_write` sin fuga de descriptores | T43, T53 |
| 5 | El orden de las promociones a ESTABLE lo FIRMA el aprobador (`qce sign --sequence N`); el campo `sequence` del manifiesto sin firmar ya no cuenta | T26 |
| 6 | `ChainLog` y `Ledger` fallan cerrado (línea cortada, entrada manipulada, bajar el nivel de reparación sin aprobador); `requires-python` ≥ 3.13 (lo que se prueba) | T67, T68 |
| 7 | Anti-DoS del servidor TLS (tope de conexiones, plazo total de apretón, vida máxima, `accept` resistente); CRL en el servidor y verificada antes de usarla; KME emulado sin bloqueo; marcador STABLE atómico y anclado; la CLI se niega fuera de un clon | T69–T72 |
| 8 | Tope por origen (`ConnectionGuard`); ancla local del número de CRL (`CrlPin`); CRL de la cadena entera (CA intermedias); plazo por operación del KME con prueba | T69, T70 |

## Límites que siguen declarados

- G5 sin cumplir: nadie ajeno al proyecto ha revisado QCE1 ni QIL1. Es el motivo de `review/`.
- Las defensas anti-DoS son de capa de aplicación: no sustituyen a un cortafuegos; detrás de NAT el tope por origen afecta a todos los usuarios de ese origen.
- El suelo del número de CRL vive en un archivo: quien lo reescriba lo baja; y la primera lista vista fija el suelo.
- `releases/STABLE` no tiene firma propia: el ancla externo (`tools/anchor.py`) detecta que lo movieron, no lo impide en local.
- Sin OCSP ni distribución automática de CRL.
- La CLI `qce` solo funciona desde un clon del repositorio.

Detalle completo: `LIMITATIONS.md` y `THREAT_MODEL.md`.

## Antes de publicar (lo hace una persona)

1. Firmar G6 sobre el `release_id` final (`python -m qce sign …`).
2. Decidir qué hacer con G5 (ver `review/GUIA_PARA_ENVIAR.md`).
3. Crear la etiqueta y el release en GitHub. Un release publicado crea un registro nuevo en Zenodo (con DOI propio): ese DOI se añade luego a `README.md` y a `CITATION.cff`.
