# Avisos de terceros / Third-party notices

Este proyecto es Apache-2.0 (ver `LICENSE` y `NOTICE`). Lo siguiente no es nuestro y se cita para que se pueda auditar.

## Se redistribuye dentro del repositorio
| Qué | Origen | Licencia / condiciones |
|---|---|---|
| Subconjuntos de **vectores oficiales de NIST ACVP** (`tests/vectors/acvp_subset.json`, `acvp_subset_high.json`, `acvp_slhdsa_subset.json`) | <https://github.com/usnistgov/ACVP-Server> (`gen-val/json-files`); procedencia, commit upstream y SHA-256 de los archivos originales dentro de cada JSON | Datos de pruebas publicados por NIST (organismo del gobierno de EE. UU.). Ese repositorio **no declara una licencia** y no se la atribuimos; se incluye solo un subconjunto con su procedencia, para pruebas de conformidad. Esto no es asesoría legal. |

## Dependencias de ejecución (no se redistribuyen: se instalan por `pip`, fijadas con hashes en `requirements.hashes.txt`)
| Paquete | Licencia (según sus metadatos) |
|---|---|
| `cryptography` | Apache-2.0 OR BSD-3-Clause |
| `cffi` | MIT-0 |
| `pycparser` | BSD-3-Clause |

Las dependencias de prueba están en `requirements-test.lock` (dentro del paquete de revisión) y tampoco se redistribuyen.

## Herramientas externas que el proyecto usa si están instaladas (no se incluyen)
OpenSSL, GnuTLS, Mozilla NSS (`tstclnt`, `selfserv`, `certutil`), SoftHSM, `pkcs11-provider`, Tamarin Prover, Docker. Cada una tiene su propia licencia y se obtiene de su fuente. El ayudante `tests/helpers/nss_psk_server.c` es código nuestro (Apache-2.0) que se **compila en la máquina de quien ejecuta las pruebas** contra la biblioteca NSS que esa persona tenga instalada; no se distribuye NSS.
`docs/hsm_lab/setup.sh` descarga `pkcs11-provider` desde su proyecto y verifica su SHA-256 antes de compilarlo; no se redistribuye su código.

## `tools/external-js-lab/` (herramienta de verificación; no entra en el `release_id`)
**No se redistribuyen**: los vectores se descargan con `fetch-vectors.sh` y se verifican por SHA-256; las herramientas se instalan por separado. Licencias según nuestro conocimiento; verifícalas en cada proyecto.
| Qué | Origen | Licencia / condiciones |
|---|---|---|
| Vectores **Wycheproof** (AES-GCM, ChaCha20-Poly1305, X25519, ML-KEM) | <https://github.com/C2SP/wycheproof> | Apache-2.0 |
| Vectores **NIST ACVP** (ML-KEM keyGen / encapDecap) | <https://github.com/usnistgov/ACVP-Server> | Ver la fila de NIST ACVP arriba: sin licencia declarada; no se redistribuyen |
| Vectores de prueba de **X-Wing** | <https://github.com/dconnolly/draft-connolly-cfrg-xwing-kem> (`spec/test-vectors.json`) | No verificada; no se redistribuyen |
| `@noble/post-quantum` 0.4.1 | npm | MIT |
| `eslint` 9.17.0, `eslint-plugin-security` 3.0.1 | npm | MIT, Apache-2.0 |
| Semgrep 1.95.0 (CLI), Tamarin Prover 1.12.0 | pip / sitio del proyecto | LGPL-2.1, GPL-3.0 (herramientas externas; no se incluyen) |
