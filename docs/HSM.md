# Servidor TLS con la clave privada en un HSM (PKCS#11)

**Estado: puente NO REVISADO por terceros, probado solo con SoftHSM (un HSM de software). Ningún HSM real, ninguna tarjeta, ningún servicio en la nube.**

## Qué hace
`qce/transport/hsm_tls.py::HsmServerContext` abre un servidor TLS 1.3 híbrido (X25519MLKEM768) cuya **clave privada de larga duración vive en un token PKCS#11 y nunca entra en este proceso**. La firma del `CertificateVerify` la hace el token; el proceso solo maneja un manejador opaco. Es la «ventanilla»: se entrega el papel, vuelve firmado, y la llave nunca sale del cajón.

```python
from qce.transport.hsm_tls import HsmServerContext
ctx = HsmServerContext("openssl-hsm.cnf", "tls.pem", "pkcs11:token=qce-lab;object=tls-key;type=private?pin-source=file:/ruta/pin")
conn = ctx.accept(sock)      # TLSv1.3 + X25519MLKEM768, atestado después del apretón
ctx.close()                  # libera solo el SSL_CTX (ver «Ciclo de vida»)
```

## Cómo funciona
1. Se carga el proveedor `pkcs11-provider` de OpenSSL en un **contexto de biblioteca propio** (`OSSL_LIB_CTX`), aislado del resto del proceso, desde el archivo de configuración de quien despliega.
2. La clave se obtiene por su **URI** con el almacén de OpenSSL (`OSSL_STORE`, tipo PKEY) y se entrega a `SSL_CTX_use_PrivateKey`.
3. Se comprueba que **no sea exportable** (se pide el parámetro privado `d` o `priv`; si el token lo entrega, se rechaza). Una clave de software disfrazada de HSM no se usa.
4. Se comprueba que el certificado corresponde a la clave del token (`SSL_CTX_check_private_key`).
5. Tras el apretón se atesta versión, grupo y suite (igual que la ruta PSK).

Falla **cerrado y sin alternativa en software**: sin proveedor, sin token, PIN erróneo o ausente, clave inexistente, URI que no sea `pkcs11:` o sin `type=private`, certificado ajeno o ilegible, suite o grupo fuera de la lista cerrada → no hay servidor. Cada caso se prueba con su propio motivo (`test_every_misconfiguration_fails_closed_…`).

## Ciclo de vida (hallazgo real, INC-0027)
Un módulo PKCS#11 se inicializa **una vez por proceso** y no debe descargarse. Al liberar el contexto de biblioteca el módulo se descargaba y el siguiente `fork()` terminaba en SIGSEGV. Por eso:
- el contexto de biblioteca se crea **una vez por archivo de configuración**, vive hasta el fin del proceso y `close()` solo libera el `SSL_CTX`;
- la configuración del laboratorio fija `pkcs11-module-quirks = no-deinit`;
- consecuencia: **un archivo de configuración de HSM por proceso** (cambiarlo crea otro contexto más, que tampoco se libera).

## PIN y revocación
- El PIN se da con `pin-source=file:` (archivo 0600) y se usa en la **primera operación del proceso**; un PIN malo o ausente se reporta como «el token no tiene esa clave privada, o no se pudo iniciar sesión». El PIN nunca se registra ni se pone en la URI.
- Retirar la clave del token bloquea los contextos **nuevos**; uno ya abierto sigue firmando hasta cerrarlo. **Revocar = reiniciar el proceso** (y revocar el certificado con la CRL, ver `docs/TLS13_TRANSPORT.md`).

## Límites de SoftHSM (afectan a las pruebas, no al diseño)
- SoftHSM falla en ECDSA por partes: las pruebas usan **RSA-2048 con RSA-PSS**. Un HSM real puede ofrecer ECDSA o ML-DSA; no se ha probado.
- SoftHSM guarda la clave en archivos del usuario: demuestra el **mecanismo** (la clave no se exporta por la interfaz), no la resistencia física de un HSM.

## Laboratorio reproducible
`docs/hsm_lab/setup.sh [carpeta]` (por defecto `~/.qce-hsm-lab`) hace todo sin instalar nada en el sistema:
1. descarga `pkcs11-provider` **v1.3.0** y comprueba su **SHA-256 fijado** (`b8bbc30c…0538`); si no coincide, aborta;
2. firma PGP: solo **informativa** (muestra la huella del firmante que informa `gpg`; la clave pública no está en tu red de confianza, compárala por otro canal). El control que bloquea es el SHA-256;
3. compila en un entorno temporal (`meson`/`ninja` desde PyPI, solo para ese paso);
4. crea un token SoftHSM con PIN aleatorios (0600) y una clave RSA **generada dentro**; emite un certificado de una CA de laboratorio (`issue_cert.py`).

Verificado el 2026-10-20 en una carpeta limpia: el binario compilado tiene el mismo SHA-256 que el anterior (`95c6abd0…37ce5`, compilación reproducible en este equipo) y las 10 pruebas pasan contra él (`QCE_HSM_PROVIDER=<carpeta>/lib/pkcs11.dylib`). Requisitos previos de Homebrew: `softhsm`, `gnutls` (`p11tool`), `pkgconf`, `openssl@3`. Las pruebas se saltan solas si faltan.

## Cómo se prueba
`tests/test_hsm_tls.py` (10 pruebas, cada escenario en un proceso aparte para poder detectar SIGSEGV), 17 mutantes `hsm-*` más `psk-attest-psk-used-off` (19/19 muertos): cliente OpenSSL real completa el apretón híbrido y verifica la firma hecha por el token; clave inextraíble y clave exportable rechazada; 12 configuraciones erróneas; PIN malo/ausente/correcto; clave retirada; fork tras cerrar; contadores exactos (SSL_CTX y SSL creados == liberados, contexto de biblioteca creado 1 vez y liberado 0); atestación.

## Qué NO está demostrado
- Ningún HSM real, tarjeta, YubiHSM, ni KMS en la nube; el comportamiento de sesiones, bloqueos y cuotas de un HSM real puede diferir.
- La firma que hace el token es clásica (RSA-PSS en las pruebas); la autenticación poscuántica del certificado (ML-DSA en un HSM) no está cubierta. El intercambio de claves sí es híbrido.
- Rotación del certificado/clave del token, copias de seguridad de la clave y control de acceso al token son responsabilidad de quien despliega.
- `pkcs11-provider` y el puente `ctypes` no han sido revisados por terceros.
