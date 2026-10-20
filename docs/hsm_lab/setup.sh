#!/usr/bin/env bash
# Laboratorio HSM reproducible: compila el proveedor PKCS#11 de OpenSSL (pkcs11-provider v1.3.0) en una carpeta APARTE (por defecto ~/.qce-hsm-lab), SIN instalar nada en el sistema.
# Requisitos previos (se instalan con Homebrew; el guion NO los instala): softhsm, gnutls (p11tool), pkgconf, openssl@3, python3 y gpg (opcional, solo informativo).
# Uso:  docs/hsm_lab/setup.sh [carpeta]   (QCE_PYTHON=ruta al Python del proyecto, por defecto .venv/bin/python; necesita `cryptography`)
#            Las pruebas (tests/test_hsm_tls.py) solo necesitan <carpeta>/lib/pkcs11.dylib.
set -euo pipefail
LAB="${1:-$HOME/.qce-hsm-lab}"
VERSION="1.3.0"
TARBALL="pkcs11-provider-$VERSION.tar.xz"
URL="https://github.com/openssl-projects/pkcs11-provider/releases/download/v$VERSION"
SHA256="b8bbc30cfb7865603fff1dd0fb516cce90437d8ddb267e331cd89d6121960538"            # fijada: se compara ANTES de compilar
for tool in softhsm2-util p11tool pkgconf python3; do command -v "$tool" >/dev/null || { echo "falta $tool (brew install softhsm gnutls pkgconf)"; exit 2; }; done
OSSL3="$(brew --prefix openssl@3)"
mkdir -p "$LAB/lib" && chmod 700 "$LAB"
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
echo "[1/4] descargando $TARBALL ($URL)"
curl -fsSL -o "$W/$TARBALL" "$URL/$TARBALL"
GOT="$(shasum -a 256 "$W/$TARBALL" | cut -d' ' -f1)"
[ "$GOT" = "$SHA256" ] || { echo "SHA-256 distinto del fijado: $GOT"; exit 3; }
echo "      SHA-256 verificado: $GOT"
if command -v gpg >/dev/null; then
  # Informativo, NO es el control: el control que bloquea es el SHA-256 fijado arriba. La huella del firmante hay que compararla por otro canal (no se fija aquí porque no se ha verificado de forma independiente).
  curl -fsSL -o "$W/$TARBALL.asc" "$URL/$TARBALL.asc"
  export GNUPGHOME="$W/gnupg"; mkdir -m 700 "$GNUPGHOME"
  echo "      firma PGP (informativa), huella del firmante que informa gpg:"
  gpg --status-fd 1 --verify "$W/$TARBALL.asc" "$W/$TARBALL" 2>&1 | grep -E "ERRSIG|NO_PUBKEY|GOODSIG|BADSIG" | sed 's/^/        /' || true
fi
echo "[2/4] compilando en un entorno temporal (meson y ninja desde PyPI, solo para este paso)"
python3 -m venv "$W/venv" && "$W/venv/bin/pip" -q install meson ninja
mkdir "$W/src" && tar -xJf "$W/$TARBALL" -C "$W/src" --strip-components=1
( cd "$W/src" && PATH="$W/venv/bin:$PATH" PKG_CONFIG_PATH="$OSSL3/lib/pkgconfig" meson setup build -Dbuildtype=release >/dev/null && PATH="$W/venv/bin:$PATH" meson compile -C build pkcs11 >/dev/null )
cp "$W/src/build/src/pkcs11.dylib" "$LAB/lib/pkcs11.dylib"
shasum -a 256 "$LAB/lib/pkcs11.dylib" | tee "$LAB/lib/pkcs11.dylib.sha256"
echo "[3/4] token de laboratorio (PIN aleatorios en archivos 0600) y clave RSA generada DENTRO del token"
mkdir -p "$LAB/tokens" && chmod 700 "$LAB/tokens"
for f in pin so-pin; do [ -f "$LAB/$f" ] || { python3 -c "import secrets,os;fd=os.open('$LAB/$f',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);os.write(fd,(secrets.token_hex(8)+'\n').encode())"; }; done
printf 'directories.tokendir = %s/tokens\nobjectstore.backend = file\nlog.level = ERROR\n' "$LAB" > "$LAB/softhsm2.conf"
export SOFTHSM2_CONF="$LAB/softhsm2.conf"
MODULE="$(brew --prefix softhsm)/lib/softhsm/libsofthsm2.so"
softhsm2-util --init-token --free --label qce-lab --so-pin "$(cat "$LAB/so-pin")" --pin "$(cat "$LAB/pin")" >/dev/null
GNUTLS_PIN="$(cat "$LAB/pin")" p11tool --provider="$MODULE" --login --generate-privkey=rsa --bits=2048 --label tls-key --id 01 "pkcs11:token=qce-lab" >/dev/null 2>&1
GNUTLS_PIN="$(cat "$LAB/pin")" p11tool --provider="$MODULE" --login --export "pkcs11:token=qce-lab;object=tls-key;type=public" 2>/dev/null > "$LAB/tls-pub.pem"
cat > "$LAB/openssl-hsm.cnf" <<CNF
# Configuración SOLO del laboratorio HSM; no es la del sistema.
openssl_conf = openssl_init
[openssl_init]
providers = provider_sect
[provider_sect]
default = default_sect
pkcs11 = pkcs11_sect
[default_sect]
activate = 1
[pkcs11_sect]
module = $LAB/lib/pkcs11.dylib
pkcs11-module-path = $MODULE
activate = 1
CNF
echo "[4/4] certificado de la CA de laboratorio para la clave pública del token (la clave privada de la CA no se guarda)"
( cd "$(dirname "$0")/../.." && "${QCE_PYTHON:-.venv/bin/python}" -I docs/hsm_lab/issue_cert.py "$LAB" )
echo "Listo. Laboratorio en $LAB. Prueba: python -m pytest tests/test_hsm_tls.py"
