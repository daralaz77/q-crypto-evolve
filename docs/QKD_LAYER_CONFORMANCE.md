# QIL1 — conformidad modelo-código

**Estado: NO REVISADA por terceros.** Qué hace y qué no, igual que `docs/QCE1_CONFORMANCE.md`: `qce/evolve/qil_conformance.py` toma trazas del CÓDIGO REAL con un atacante activo
(`tests/qkd_layer_scenarios.py conformance`, en un proceso nuevo y sobre TLS 1.3 real) y comprueba, con código independiente escrito solo desde `docs/QKD_LAYER_SPEC.md`, que son trazas del modelo `formal/qil1.spthy`.

## Sesiones observadas (7)
honesta; reutilización tras completar; atacante que conoce el id y envía una etiqueta falsa; cliente legítimo justo después; HELLO malformado; cliente con clave equivocada; MITM con certificado falso que retransmite al servidor real.
De cada una se registran los mensajes de cada extremo, el valor de ligadura y el certificado que vio cada uno, y las llamadas del servidor a su fuente de claves (`reserve`/`commit`/`release`).

## Qué se comprueba
1. Se recalculan `th`, las etiquetas y las claves y se convierten las sesiones en eventos del modelo (`ClientStart`, `ServerStart`, `ClientDone`, `ServerDone`, `ServerAbort`).
2. **Lemas sobre las trazas:** `channel_agreement`, `server_agreement`, `client_authenticated_by_qkd`, `key_single_use`, `no_reuse_after_done`.
3. **Guardas** (los `Eq` del modelo): el código solo acepta si la guarda independiente se cumple (nunca más permisivo que el modelo) y acepta cuando se cumple. El servidor debe reservar si y solo si la clave estaba disponible, y hacer exactamente un `commit` o un `release` tras reservar.
4. **El verificador tiene dientes** (`tests/test_qil_conformance.py`): se manipulan las trazas (cliente que acepta en el MITM, servidor que consume sin etiqueta, que no devuelve la clave, que toca la fuente con un HELLO malformado, ACCEPT con etiqueta equivocada) y cada manipulación se detecta.

## Resultado
7 sesiones, 0 problemas; eventos observados: 2 `ClientDone` y 2 `ServerDone` (sesiones 1 y 4), 3 `ServerAbort` (3, 6 y 7). En el MITM con certificado falso el servidor real inicia y aborta, el cliente no completa, y el valor de ligadura y el certificado de ambos extremos difieren: exactamente lo que el modelo predice con la ligadura.

## Límites
- Son trazas observadas, no una prueba del código ni de las primitivas; 7 sesiones no agotan el espacio de ataques.
- El modelo acota los abortos a uno por clave; el código admite más, y la conformidad solo lo cubre con las pocas sesiones observadas.
- No cubre la capa de registros (se prueba aparte en `tests/test_qkd_layer.py`).
- El oráculo lo escribió la misma instancia que el código; no hay revisión humana.
