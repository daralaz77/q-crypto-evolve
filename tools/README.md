# Herramientas (fuera del `release_id`)

- `cbom.py`: genera la CBOM (CycloneDX 1.6) desde la política real (`qce.core.policy.SUITES`). `python tools/cbom.py > benchmarks/cbom.cdx.json`; `--check` falla si el archivo está desactualizado. **No validada contra el esquema oficial** (no hay validador instalado); `tools/tests` comprueba la estructura usada. Marca como vulnerables a un ordenador cuántico X25519, Ed25519 y la PKI ECDSA P-256 del transporte TLS.
- Pruebas: `python -m pytest tools/tests -o addopts= -q`.
