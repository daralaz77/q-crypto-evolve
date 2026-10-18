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
# QIL1 se ejecuta en el mismo comando (formal/qil1.spthy, formal/expected_qil1.json); a mano:
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

Máquina: macOS (Apple Silicon), Python 3.14.7, `cryptography` 50.0.2, OpenSSL 3.6.4 (Homebrew), Tamarin 1.12.0, Maude 3.5.1. Todo desde el `.zip`, en un directorio vacío y con un entorno virtual nuevo
(paquete inmediatamente anterior a este texto: mismo código, solo cambia esta guía).

| Paso | Resultado observado |
|---|---|
| §1 `shasum -a 256 -c MANIFEST.sha256` | 0 discrepancias |
| §3 `pytest` completo | **389 passed, 11 skipped**, ≈ 52 s (omitidas: 3 pruebas formales pesadas que exigen `QCE_FORMAL=1` y 8 del propio empaquetado, que solo corren en el repositorio completo) |
| §4 `python -m qce formal` | «modelo formal: veredictos y mutantes del modelo conformes…»: QCE1 (11 configuraciones, 3 mutantes) **y** QIL1 (8 configuraciones, 5 mutantes) |
| §5 `python -m qce mutate` | **no reproducido desde el zip en esta ocasión** (≈ 25 min). Resultado en el repositorio completo: ~300 mutantes, todos los puntuables detectados, 5 equivalentes declarados con su justificación |

Pruebas que dependen del entorno: el transporte PSK, SLH-DSA y la interoperabilidad con la herramienta `openssl` necesitan un OpenSSL ≥ 3.5 (se omiten o fallan cerrado si no está; ver `docs/TLS13_PSK_TRANSPORT.md`). Probado solo en macOS con Homebrew.

Dos cosas que conviene saber: las pruebas de mutación y formales usan varios núcleos; y `pip-audit` (auditoría de dependencias) **no** forma parte de este paquete porque necesita red y la base pública de vulnerabilidades.

## 7. Si algo no coincide

Un resultado distinto del esperado **es un hallazgo**: anótelo en `PLANTILLA_INFORME.md` indicando versión de Python, sistema operativo y salida completa.
