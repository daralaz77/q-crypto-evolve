# Guía de reproducción

Todo lo que el paquete afirma se puede volver a ejecutar. Esta guía se probó **en un directorio vacío, con un entorno virtual nuevo**, a partir del `.zip` (resultados reales en §6).

## 0. Requisitos

| Para | Necesita |
|---|---|
| Pruebas y conformidad | Python ≥ 3.11 (probado con 3.14.7), acceso a PyPI para instalar `cryptography==50.0.2` y las herramientas de prueba |
| Modelo formal (opcional) | Tamarin Prover 1.12.0 y Maude 3.5.1 (ver <https://tamarin-prover.com>; en macOS con Homebrew: `brew trust tamarin-prover/tap` y `brew install tamarin-prover/tap/tamarin-prover` — confíe en ese tap solo si lo decide usted) |
| Prueba de mutación (opcional) | lo mismo que las pruebas; tarda varios minutos |

No hace falta red durante la ejecución de las pruebas una vez instaladas las dependencias.

## 1. Comprobar la integridad

```sh
shasum -a 256 qce1-review-<id>.zip          # compárelo con el hash que le comunicaron por OTRO canal
unzip qce1-review-<id>.zip -d qce1-review && cd qce1-review
shasum -a 256 -c MANIFEST.sha256            # todos los archivos deben decir OK
```

El manifiesto **no está firmado**: el único ancla de confianza es el hash del `.zip` recibido por otro canal.

## 2. Entorno

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements.lock -r requirements-test.lock
```

## 3. Pruebas

```sh
.venv/bin/python -m pytest                   # batería completa; las pruebas formales pesadas se omiten sin QCE_FORMAL=1
.venv/bin/python -m pytest tests/test_official_vectors.py -v      # vectores oficiales NIST ACVP (65 casos)
.venv/bin/python -m pytest tests/test_spec_anchors.py -v          # la especificación re-derivada con código independiente
.venv/bin/python -m pytest tests/test_conformance.py -v           # trazas del código real frente al modelo
```

## 4. Modelo formal

```sh
.venv/bin/python -m qce formal               # matriz de 11 configuraciones y 3 mutantes del modelo, frente a formal/expected.json
# o bien, a mano:
cd formal && ./run_all.sh                    # imprime  configuración|lema|tipo|veredicto
tamarin-prover qce1.spthy --prove -DBREAKX -DBREAKM   # una configuración concreta (prueba de que el secreto se rompe si caen ambos KEM)
```

Para ver el modelo con ojos críticos: abra `formal/qce1.spthy`, cambie una regla (por ejemplo, quite `Eq(vere(...), true)` de `C2_client_finish`) y compruebe qué lema cae. `qce/evolve/formal.py` hace tres de esas pruebas automáticamente.

## 5. Prueba de mutación (opcional)

```sh
.venv/bin/python -m qce mutate               # rompe a propósito cada control de seguridad y exige que alguna prueba falle
```

Resultado esperado: `survivors: []`, con un mutante «canario» sin efecto que debe sobrevivir (si fuera detectado, el arnés no sería fiable).

## 6. Resultados observados al reproducir desde cero

Máquina: macOS (Apple Silicon), Python 3.14.7, `cryptography` 50.0.2, pytest 9.1.1, hypothesis 6.170.1, Tamarin 1.12.0, Maude 3.5.1. Todo desde el `.zip`, en un directorio vacío y con un entorno virtual nuevo.

| Paso | Resultado observado |
|---|---|
| §1 `shasum -a 256 -c MANIFEST.sha256` | todos los archivos `OK` (0 discrepancias) |
| §3 `pytest` completo | **279 passed, 10 skipped**, ≈ 25 s (los 10 omitidos: 2 pruebas formales pesadas que exigen `QCE_FORMAL=1`, y 8 pruebas del propio empaquetado, que solo corren en el repositorio completo) |
| §3 vectores oficiales NIST | 66 passed (65 casos de ACVP: 25 ML-KEM-768 keyGen, 25 ML-DSA-65 keyGen, 15 ML-DSA-65 sigVer; + 1 comprobación de que hay casos negativos) |
| §3 especificación anclada | 6 passed |
| §3 conformidad con el modelo | 11 passed |
| §4 `python -m qce formal` | «modelo formal: veredictos y mutantes del modelo conformes a formal/expected.json», ≈ 92 s con 4 procesos en paralelo |
| §5 `python -m qce mutate` | 140 mutantes: **135 detectados de 135 puntuables**, `survivors: []`, `canary_ok: true`, 4 declarados equivalentes (con su justificación en `qce/evolve/mutation.py`); ≈ 12 min con la máquina compartida con otras tareas |

Dos cosas que conviene saber: las pruebas de mutación y formales usan varios núcleos; y `pip-audit` (auditoría de dependencias) **no** forma parte de este paquete porque necesita red y la base pública de vulnerabilidades.

## 7. Si algo no coincide

Un resultado distinto del esperado **es un hallazgo**: anótelo en `PLANTILLA_INFORME.md` indicando versión de Python, sistema operativo y salida completa.
