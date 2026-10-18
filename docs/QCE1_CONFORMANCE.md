# Conformidad modelo-código de QCE1 (paso 6)

**Pregunta:** ¿el código Python de QCE1 hace lo que dice el modelo formal (`formal/qce1.spthy`)?
**Respuesta corta:** en todas las trazas observadas, sí; y el código reproduce las dos falsificaciones del modelo que se podían reproducir. No es una prueba de equivalencia: es una batería de **verificación en ejecución de las fórmulas del modelo sobre el código real** (runtime verification).

Implementación: `qce/evolve/conformance.py` · pruebas: `tests/test_conformance.py` (11 pruebas, ≈1 s).

## 1. Método

1. Un atacante activo controla la red entre un cliente y un servidor **reales** (`ClientHandshake`, `ServerHandshake`): deja pasar, descarta, altera un byte o sustituye un mensaje por otro de una sesión anterior.
2. Cada ejecución se convierte en **eventos con los nombres y argumentos de las acciones del modelo** (`ClientStart`, `ServerStart`, `ClientFinishSent`, `ServerDone`, `ClientDone`, `RevealLTK`). Los argumentos (transcript, claves, ofertas, suite) se **recalculan con código independiente escrito desde la especificación**; no se reutiliza ninguna función de derivación de `qce`.
3. Sobre las trazas se evalúan las fórmulas de los lemas: acuerdo inyectivo, anti-degradación y «la firma liga los Hello» (con la salvedad `RevealLTK` del modelo).
4. En cada paso con **guarda** (los `Eq(...)` de las reglas C2, S2 y C3 del modelo) se calcula la guarda con el oráculo independiente y se compara con la decisión del código:
   - el código **no puede aceptar** si la guarda no se cumple (sería más permisivo que el modelo);
   - si rechaza algo que el modelo aceptaría, solo se admite por controles propios que el modelo abstrae (`PolicyViolation`, `MalformedMessage`).
5. Se **reproducen en el código real** las dos falsificaciones del modelo con roturas: identidad del servidor revelada (≈ Ed25519 + ML-DSA rotos) y clave KEM efímera filtrada (≈ X25519 + ML-KEM rotos).

## 2. Resultados

| Comprobación | Resultado |
|---|---|
| Ejecución honesta = traza `executable` del modelo (orden de eventos exacto), con ChaCha, con AES-GCM y con QKD | conforme |
| 400 sesiones con atacante de red aleatorio (semilla fija; ≥ 80 completadas y rechazos en C2, S2 y C3) | 0 violaciones de lemas, 0 decisiones más permisivas que el modelo |
| Alteración sistemática del primer, segundo, central y último byte de cada mensaje (16 sesiones) | conforme; ninguna produce `ClientDone` sin `ServerDone` |
| Servidor impostor con otra identidad | el cliente rechaza en C2; la guarda del modelo también es falsa |
| Identidad revelada: el atacante hace de servidor y el cliente termina | **el ataque funciona en el código**, y la traza viola acuerdo y firma exactamente como el modelo dice para `breakED`; solo la excusa el evento `RevealLTK`. Sin ese evento sería un ataque |
| Clave KEM efímera filtrada: el atacante termina al cliente sin el servidor | **el ataque funciona en el código**; viola acuerdo y secreto y **no** viola «la firma liga los Hello», exactamente la fila `breakXM` de `formal/expected.json` |

## 3. Qué detecta (probado con derivas del código)

Mutantes del código añadidos a la prueba de mutación (`qce/evolve/mutation.py`, prefijo `conf-`), todos detectados:

| Deriva introducida | ¿Detectada sin las pruebas de conformidad, spec y formal? |
|---|---|
| El servidor compara solo 16 de los 32 bytes del MAC del cliente | **No: sobrevivía a toda la batería anterior** |
| El cliente compara solo 16 bytes del MAC del servidor | sí |
| Se quita la huella de identidad de lo firmado | sí |
| El texto cifrado del KEM sale del transcript | sí |

El primero es un hueco real de la batería previa, cerrado por la alteración sistemática de bytes (registrado como INC-0018).

## 4. Dónde el código es **más estricto** que el modelo (permitido, y documentado)

- **Un solo intento:** el modelo permite que el servidor reciba otro `ClientFinish` tras uno inválido (la regla S2 no se consume si falla su guarda); el código cierra el apretón al primer fallo.
- **Política de suites, longitudes y formato:** el modelo abstrae `pick` y las longitudes; el código rechaza suites no permitidas, campos con longitud inválida o bytes sobrantes.
- **Cliente:** el código comprueba que la suite elegida esté entre las ofrecidas; el modelo no.

## 5. Límites (lo que esto NO demuestra)

- **No cubre toda la entrada posible:** son 400 sesiones aleatorias y 16 sistemáticas más los ataques dirigidos; un fallo que exija una combinación improbable puede no aparecer.
- **El oráculo y las derivaciones son otra implementación escrita por la misma instancia que el código y el modelo.** Reduce el riesgo de deriva, no sustituye a una segunda persona.
- **El modelo no es el código:** los eventos se calculan desde fuera con fórmulas de la especificación; lo que el código haga internamente y no se vea en esos eventos no se comprueba.
- **Secreto:** la traza solo puede comprobar que el atacante simulado no obtiene claves salvo en los ataques dirigidos; no puede probar que ningún atacante cualquiera lo consiga (eso es el trabajo del modelo y de la criptografía subyacente).
- **Las primitivas se usan reales** (no hay «rotura» de ML-KEM en el código); la rotura se emula dando al atacante la clave efímera o la identidad.
- Sigue pendiente la **revisión de una persona experta** del modelo, de la especificación y de esta conformidad.
