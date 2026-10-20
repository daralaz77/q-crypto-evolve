# Cadena de suministro: hashes de dependencias y SBOM

**Código:** `qce/evolve/supply_chain.py` · **Pruebas:** `tests/test_supply_chain.py`, `tests/test_audit_findings.py::test_gate_g1_blocks_when_dependency_hashes_or_sbom_are_missing_or_incoherent` · **Comandos:** `python -m qce supply-chain` y `python -m qce supply-chain --check`.

## Qué hay
- `requirements.lock`: las tres dependencias de ejecución fijadas (`cffi`, `cryptography`, `pycparser`). Sin cambios de formato (otros módulos lo leen línea a línea).
- `requirements.hashes.txt`: las mismas versiones con el SHA-256 de **todos** los archivos que PyPI publica para esa versión (sdist y ruedas de todas las plataformas). Sirve para `pip install --require-hashes -r requirements.hashes.txt`.
- `sbom.cdx.json`: lista de materiales CycloneDX 1.5, determinista (sin fecha ni UUID aleatorio; el número de serie sale del contenido), con `purl`, licencia declarada y el hash del sdist. **Solo** las dependencias de ejecución, no las de prueba (`pytest`, `hypothesis`).
- La puerta **G1** comprueba, sin red, que los tres archivos son coherentes entre sí; los dos nuevos entran en el `release_id`.

## Qué se probó de verdad (2026-10-19)
- **Instalación limpia con `--require-hashes`** en un entorno virtual nuevo: instala exactamente `cffi==2.1.1`, `cryptography==50.0.2`, `pycparser==3.11` y `cryptography` se importa.
- **Con todos los hashes de un paquete alterados**, `pip` se niega («THESE PACKAGES DO NOT MATCH THE HASHES», código 1) y no instala nada. (Alterar solo uno de los hashes de un paquete no basta para que falle: `pip` acepta el archivo si coincide cualquiera de los listados.)
- **Un paquete que no está en el archivo** (por ejemplo `requests`) es rechazado en modo `--require-hashes`.

## Límites
- Los hashes los publica PyPI. Cubren que nadie sustituya un archivo **después** de publicado; no protegen de una dependencia ya maliciosa en su origen, ni de un PyPI comprometido en el momento de generar.
- Generar requiere red de **solo lectura** hacia `pypi.org` (API JSON, no descarga archivos); comprobar no.
- Un archivo con muchas ruedas de plataformas deja muchos hashes aceptables; para un despliegue concreto convendría fijar solo el de su plataforma.
- No hay firma del SBOM ni atestación de procedencia (SLSA/sigstore).
- `pip-audit` sigue necesitando red; `requirements-test.lock` no existe en el repositorio (solo se genera dentro del paquete de revisión).
