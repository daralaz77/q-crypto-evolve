# Kit: servidor TLS con la clave en un HSM de la nube (Google Cloud KMS con protección HSM)

**Estado: NO PROBADO contra Google.** Lo único probado es la lógica de `verify_kms.py` usando SoftHSM como sustituto (`--selftest-softhsm`: 3/3 conexiones verificadas, firma `rsa_pss_rsae_sha256`). Todo lo demás es preparación basada en la guía de usuario de la biblioteca ([kmsp11](https://github.com/GoogleCloudPlatform/kms-integrations/blob/master/kmsp11/docs/user_guide.md), leída el 2026-10-20) y en mi conocimiento de `gcloud`, **marcado «revisar» donde no lo verifiqué**. Este kit está **fuera de las puertas** (`docs/`, no `qce/` ni `tests/`) a propósito: no se mezcla código sin probar con el sistema verificado.

## Lo que dice la guía de la biblioteca (verificado)
- **Solo Linux amd64** (probada en Ubuntu 20.04, glibc ≥ 2.29) **y Windows**. No hay macOS.
- Firma con `CKM_RSA_PKCS_PSS` (claves `RSA_SIGN_PSS_2048/3072/4096_SHA256`) y con `CKM_ECDSA` (P-256, P-384).
- Autentica con la **cuenta de servicio de la VM**; `C_Login` se acepta y el **PIN se ignora**.
- Configuración en un YAML (`KMS_PKCS11_CONFIG`), que debe ser escribible solo por su dueño.
- Opción `skip_fork_handlers` (relevante por INC-0027).

## Lo que NO sabemos (el verificador lo mide)
1. Si la clave pública de una clave `RSA_SIGN_PSS` sirve como certificado TLS (tipo `rsaEncryption` frente a `RSASSA-PSS`). **Es el riesgo técnico más probable.** Si falla, probar `EC_SIGN_P256_SHA256` (ECDSA) cambiando el algoritmo al crear la clave.
2. Si `pkcs11-provider` 1.3.0 funciona con esta biblioteca, y si la clave aparece como no exportable.
3. Cuánto tarda cada apretón (cada firma pasa por la red).
4. Que cerrar contextos y hacer `fork()` no mate el proceso con este módulo.

## Dinero y seguridad (léelo antes de crear nada)
- **Fija un tope de presupuesto y una alerta en la consola de Google Cloud antes de empezar.** No verifiqué precios: mira la página de precios de Cloud KMS (claves HSM) y de Compute Engine.
- Usa un **proyecto desechable**. Que yo sepa, los *key rings* y las claves de Cloud KMS **no se pueden borrar**, solo programar la destrucción de sus versiones (**revisar**); la forma limpia de terminar es eliminar el proyecto entero.
- **Ninguna credencial pasa por el chat.** La VM usa una cuenta de servicio adjunta: **no descargues ni pegues un archivo de clave JSON**. Yo no necesito ni debo ver contraseñas, tokens ni claves de API.
- Cada orden que cree recursos o cueste dinero la ejecutas tú, o yo solo con tu permiso explícito y paso a paso.

## Pasos
Sustituye `PROYECTO`, la región y la zona. **Revisa cada comando con `--help` antes de ejecutarlo.**

```bash
# 1) APIs y cuenta de servicio de la VM (revisar)
gcloud services enable cloudkms.googleapis.com compute.googleapis.com --project PROYECTO
gcloud iam service-accounts create qce-hsm-lab --project PROYECTO

# 2) Conjunto de claves y clave con protección HSM (algoritmo RSA-PSS 2048; revisar los nombres de las opciones)
gcloud kms keyrings create qce-lab --location us-central1 --project PROYECTO
gcloud kms keys create qce-tls --keyring qce-lab --location us-central1 --project PROYECTO \
  --purpose asymmetric-signing --default-algorithm rsa-sign-pss-2048-sha256 --protection-level hsm

# 3) Permisos MÍNIMOS para la cuenta de servicio, solo sobre ese conjunto de claves (revisar los roles):
#    la guía pide listar, ver la clave pública y firmar (cryptoKeys.list, cryptoKeyVersions.list, viewPublicKey, useToSign)
for ROLE in roles/cloudkms.viewer roles/cloudkms.signerVerifier; do
  gcloud kms keyrings add-iam-policy-binding qce-lab --location us-central1 --project PROYECTO \
    --member serviceAccount:qce-hsm-lab@PROYECTO.iam.gserviceaccount.com --role "$ROLE"
done

# 4) VM Linux amd64 con esa cuenta de servicio (revisar imagen/zona; comprueba luego `openssl version`)
gcloud compute instances create qce-hsm-vm --project PROYECTO --zone us-central1-a --machine-type e2-small \
  --image-family ubuntu-2404-lts-amd64 --image-project ubuntu-os-cloud \
  --service-account qce-hsm-lab@PROYECTO.iam.gserviceaccount.com --scopes cloud-platform
```

### Llevar el código a la VM (sin dar acceso al repositorio privado)
```bash
git archive --format=tar.gz -o /tmp/qce.tgz HEAD            # en este Mac, desde la raíz del repositorio
gcloud compute scp /tmp/qce.tgz qce-hsm-vm:~ --zone us-central1-a --project PROYECTO
gcloud compute ssh qce-hsm-vm --zone us-central1-a --project PROYECTO
# en la VM:
mkdir qce && tar -xzf qce.tgz -C qce && cd qce
```

### En la VM
```bash
# a) Herramientas. Cada descarga exige su SHA-256 tomado por TI de la fuente oficial (el script no inventa hashes).
#    pkcs11-provider 1.3.0 ya lleva su hash verificado. Si `openssl version` ya es >= 3.5, no hace falta OPENSSL_*.
KMSP11_URL=<url del .tar.gz de libkmsp11 en las versiones de GitHub> KMSP11_SHA256=<hash> \
  OPENSSL_VERSION=<3.5.x> OPENSSL_SHA256=<hash> docs/hsm_cloud/setup_linux.sh
export QCE_LIBSSL=<la ruta libssl.so.3 que imprime el script>   # que los puentes usen ESE OpenSSL (>= 3.5)

# b) Entorno de Python con los requisitos con hashes del repositorio
python3 -m venv .venv && .venv/bin/pip install --require-hashes -r requirements.hashes.txt

# c) Clave pública -> certificado de laboratorio (la privada NUNCA sale del HSM)
mkdir lab && gcloud kms keys versions get-public-key 1 --key qce-tls --keyring qce-lab --location us-central1 --project PROYECTO --output-file lab/tls-pub.pem
.venv/bin/python -I docs/hsm_lab/issue_cert.py lab          # crea lab/tls.pem y lab/ca/ca.pem

# d) Configuraciones a partir de los ejemplos (edita las rutas y el proyecto); el YAML debe ser chmod 600
cp docs/hsm_cloud/kmsp11.yaml.example lab/kmsp11.yaml && chmod 600 lab/kmsp11.yaml
cp docs/hsm_cloud/openssl-kms.cnf.example lab/openssl-kms.cnf

# e) Verificación (sin PIN: la biblioteca lo ignora)
KMS_PKCS11_CONFIG=lab/kmsp11.yaml .venv/bin/python docs/hsm_cloud/verify_kms.py \
  --config lab/openssl-kms.cnf --cert lab/tls.pem --ca lab/ca/ca.pem \
  --uri 'pkcs11:token=qce-lab;object=qce-tls;type=private' --openssl <openssl >= 3.5> --n 20
```

## Cómo leer el resultado
- `ok: true` con `firmas: ["rsa_pss_rsae_sha256"]` y `conn` con `X25519MLKEM768`: funciona; anota la mediana de `ms_por_apreton`.
- `error` al cargar la clave («el token no tiene esa clave privada…»): revisa token, etiqueta (`object=` es el nombre de la clave en Cloud KMS) y permisos; si pide PIN, prueba añadir `?pin-value=0000` (la guía dice que se ignora; **revisar**).
- Fallo al emitir el certificado o `verificacion_ok: false`: sospecha del tipo de clave pública (riesgo 1); repite con ECDSA.
- Cuelgue o caída al final: es el `fork` (riesgo 4); prueba `skip_fork_handlers: true` en el YAML.

**Después de esto**, pásame la línea JSON (sin secretos). Si funciona, convierto lo aprendido en pruebas reales dentro de la suite y repetimos puertas; si no, lo documentamos como límite medido.

## Limpieza
Elimina el proyecto desechable (`gcloud projects delete PROYECTO`, **revisar**) o, como mínimo, borra la VM y programa la destrucción de las versiones de la clave. Comprueba en la consola que ya no hay recursos facturables.
