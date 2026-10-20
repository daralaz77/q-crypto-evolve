#!/usr/bin/env bash
# Prepara una VM Linux amd64 (Ubuntu >= 22.04) para probar el servidor TLS con la clave en Google Cloud KMS (HSM). NO PROBADO: no existe aún la VM.
#
# «Fijar o negarse»: cada descarga exige su SHA-256, que tú obtienes de la fuente oficial por OTRO canal y pasas como variable. El script NO inventa hashes
# y se niega a continuar sin ellos (así no instalas nada que no hayas verificado). El único hash que sí traemos verificado es el de pkcs11-provider 1.3.0.
#
#   OPENSSL_VERSION=3.5.x OPENSSL_SHA256=<hash> KMSP11_URL=<url del .tar.gz de la versión> KMSP11_SHA256=<hash> ./setup_linux.sh
# Si `openssl version` ya es >= 3.5 en la imagen, no hace falta OPENSSL_*: el script lo detecta y lo omite.
set -euo pipefail
PREFIX="${PREFIX:-/opt/qce-hsm}"
need() { [ -n "${!1:-}" ] || { echo "falta $1 (pásalo tomándolo de la fuente oficial; el script no inventa hashes)"; exit 2; }; }
sudo apt-get update -qq && sudo apt-get install -y -qq build-essential pkg-config python3-venv python3-pip curl ca-certificates meson ninja-build libssl-dev >/dev/null
sudo mkdir -p "$PREFIX/lib" && sudo chown -R "$USER" "$PREFIX"
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
verify() { [ "$(sha256sum "$1" | cut -d' ' -f1)" = "$2" ] || { echo "SHA-256 distinto del fijado para $1"; exit 3; }; echo "  SHA-256 verificado: $(basename "$1")"; }

OSSL=""
if openssl version | grep -qE "OpenSSL 3\.([5-9]|[1-9][0-9])|OpenSSL [4-9]\."; then
  OSSL="$(dirname "$(dirname "$(command -v openssl)")")"; echo "[1/4] OpenSSL del sistema ya es >= 3.5 ($(openssl version)); no se compila otra"
else
  need OPENSSL_VERSION; need OPENSSL_SHA256
  echo "[1/4] compilando OpenSSL $OPENSSL_VERSION en $PREFIX/openssl"
  curl -fsSL -o "$W/openssl.tgz" "https://github.com/openssl/openssl/releases/download/openssl-$OPENSSL_VERSION/openssl-$OPENSSL_VERSION.tar.gz"
  verify "$W/openssl.tgz" "$OPENSSL_SHA256"
  mkdir "$W/ossl" && tar -xzf "$W/openssl.tgz" -C "$W/ossl" --strip-components=1
  ( cd "$W/ossl" && ./Configure --prefix="$PREFIX/openssl" --libdir=lib >/dev/null && make -j"$(nproc)" >/dev/null && make install_sw >/dev/null )
  OSSL="$PREFIX/openssl"
fi

echo "[2/4] pkcs11-provider 1.3.0"
VERSION="1.3.0"; T="pkcs11-provider-$VERSION.tar.xz"
curl -fsSL -o "$W/$T" "https://github.com/openssl-projects/pkcs11-provider/releases/download/v$VERSION/$T"
verify "$W/$T" "b8bbc30cfb7865603fff1dd0fb516cce90437d8ddb267e331cd89d6121960538"
mkdir "$W/src" && tar -xJf "$W/$T" -C "$W/src" --strip-components=1
( cd "$W/src" && PKG_CONFIG_PATH="$OSSL/lib/pkgconfig:$OSSL/lib64/pkgconfig" meson setup build -Dbuildtype=release >/dev/null && meson compile -C build pkcs11 >/dev/null )
cp "$W/src/build/src/pkcs11.so" "$PREFIX/lib/pkcs11.so"; sha256sum "$PREFIX/lib/pkcs11.so"

echo "[3/4] libkmsp11 (biblioteca PKCS#11 de Google)"
need KMSP11_URL; need KMSP11_SHA256
curl -fsSL -o "$W/kmsp11.tgz" "$KMSP11_URL"; verify "$W/kmsp11.tgz" "$KMSP11_SHA256"
mkdir -p /opt/kmsp11 2>/dev/null || sudo mkdir -p /opt/kmsp11 && sudo chown -R "$USER" /opt/kmsp11
tar -xzf "$W/kmsp11.tgz" -C /opt/kmsp11 --strip-components=1 && find /opt/kmsp11 -name 'libkmsp11.so' | head -1

echo "[4/4] (el entorno de Python se crea después, con los requisitos con hashes del repositorio: ver README)"
echo "Listo. Siguiente: copia el repositorio (git archive), crea kmsp11.yaml y openssl-kms.cnf a partir de los .example y ejecuta verify_kms.py (ver docs/hsm_cloud/README.md)."
echo "QCE_LIBSSL=$(find "$OSSL" -name libssl.so.3 | head -1)   # exporta esto para que los puentes usen ESE OpenSSL"
