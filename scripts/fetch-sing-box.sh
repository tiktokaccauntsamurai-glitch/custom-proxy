#!/bin/sh
# Скачивает зафиксированную версию sing-box в bin/ и проверяет SHA256 (macOS, Linux).
# Хеши сверены с digest ассетов релиза на GitHub.
set -eu
VERSION=1.14.3
# PLATFORM=Linux-aarch64 — скачать под другую платформу (сборка релиза: package-linux.sh).
PLATFORM="${PLATFORM:-$(uname -s)-$(uname -m)}"
case "$PLATFORM" in
  Darwin-arm64)  ARCH=darwin-arm64; SHA=0360ce634a04c26a6b4fd957517987bb4f6c8950f63435ce3c5af2fcae5860c5 ;;
  Darwin-x86_64) ARCH=darwin-amd64; SHA=6d002b74d03b478547349cc10af89e007868596e5aa931816d45da9f544715a9 ;;
  Linux-x86_64)  ARCH=linux-amd64;  SHA=e2bdf179c15a3652955dc44867e33ca0965c9c9b91b34267dcc5a5d639a5feee ;;
  Linux-aarch64|Linux-arm64) ARCH=linux-arm64; SHA=29dae24d76bea3bc62d07dd3e60cfc12003de7debbd6b768df9be9c68360174e ;;
  *) echo "unsupported platform: $PLATFORM" >&2; exit 1 ;;
esac
# shasum есть в macOS, в Linux обычно sha256sum.
sha256_check() { if command -v sha256sum >/dev/null 2>&1; then sha256sum -c - >/dev/null; else shasum -a 256 -c - >/dev/null; fi; }
NAME="sing-box-$VERSION-$ARCH"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# BIN_DIR — куда положить ядро (по умолчанию <repo>/bin).
BIN_DIR="${BIN_DIR:-$ROOT/bin}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
curl -fsSL -o "$TMP/$NAME.tar.gz" "https://github.com/SagerNet/sing-box/releases/download/v$VERSION/$NAME.tar.gz"
echo "$SHA  $TMP/$NAME.tar.gz" | sha256_check
tar -xzf "$TMP/$NAME.tar.gz" -C "$TMP"
mkdir -p "$BIN_DIR"
install -m 755 "$TMP/$NAME/sing-box" "$BIN_DIR/sing-box"
echo "sing-box $VERSION ($ARCH) -> $BIN_DIR/sing-box"
