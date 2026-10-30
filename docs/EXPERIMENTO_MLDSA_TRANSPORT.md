# Experimento: autenticación ML-DSA en el transporte TLS 1.3 de qce (rama `exp/mldsa-transport`)

**Estado: experimental, solo en esta rama. NO está en `main`.** Esta rama cambia `qce/` y `tests/`, así que tiene OTRO `release_id` que el firmado en `main` (7904c2a4…): nada de lo firmado se aplica aquí, no se han repetido las puertas ni la mutación, y ninguna persona ha revisado el cambio.

## Qué cambia
- `qce/transport/pki.py`: `issue_ca`, `issue_leaf` aceptan `algorithm` = `ecdsa-p256` (por defecto, comportamiento de siempre), `ml-dsa-65` o `ml-dsa-87`; ayudantes `new_private_key` y `signing_hash` (ML-DSA firma sin resumen previo: `algorithm=None`). `sign_csr` e `issue_crl` firman con la CA del algoritmo que sea.
- `qce/transport/custody.py`: `provision_key`, `provision_with_lab_ca` aceptan `algorithm`; la CSR se firma con el algoritmo de la clave custodiada.
- `tests/mldsa_scenarios.py` y `tests/test_tls13_mldsa_transport.py`: 14 pruebas con escenarios en proceso nuevo (regla de importación de OpenSSL).

## Qué se comprobó (real, en este equipo)
- Apretón TLS 1.3 con el transporte REAL (`server_context`/`client_context`/`TlsServer`) con certificados ML-DSA-65 y ML-DSA-87 y X25519MLKEM768; el OID de la firma del certificado es el de ML-DSA (2.16.840.1.101.3.4.3.18 / .19).
- Autenticación mutua con certificado de cliente ML-DSA; sin certificado de cliente el servidor rechaza.
- Rechazo de una CA ajena, de un nombre equivocado y de un certificado revocado por una CRL firmada con ML-DSA (los tres como `SSLCertVerificationError`); el no revocado conecta.
- Clave de servidor ML-DSA custodiada por el `KeyStore`: sirve y no deja ninguna clave privada en claro en disco.
- Suite completa en la rama: 625 pruebas pasan; fallan las 2 de NSS por INC-0035 (red solo IPv4 de este equipo, no relacionado).
- Tamaño (de `conformance/tls_mldsa_probe.py` en `main`): mensajes del servidor ECDSA P-256 1.794 B, ML-DSA-65 10.155 B, ML-DSA-87 13.431 B; certificado hoja 434 / 5.558 / 7.516 B.

## Qué NO se comprobó
- Puertas G1–G6, mutación (no hay mutantes para el código nuevo), análisis de CodeQL y revisión humana.
- Interoperabilidad con NSS y GnuTLS usando certificados ML-DSA; la ruta de HSM (`hsm_tls.py`, RSA-PSS en SoftHSM; no hay ML-DSA en el token).
- Cadenas con CA intermedia, rotación automática, rendimiento (latencia, CPU) y MTU/ventana de congestión en redes reales.
- Que `pki.py` siga siendo solo de laboratorio: las claves privadas de la CA/hoja se escriben en disco con permisos 0600.

## Cómo seguir
1. Si se quiere llevar a `main`: va en el **paquete único de la Fase 2** (cambia `release_id`: repetir puertas y volver a firmar G6), idealmente con la revisión humana (G5) y mutantes nuevos para `signing_hash`/`new_private_key`.
2. Antes: probar NSS/GnuTLS con certificados ML-DSA y medir latencia.
