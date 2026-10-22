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
