#!/bin/sh
# Скачивает зафиксированную версию sing-box в bin/ и проверяет SHA256 (macOS).
set -eu
VERSION=1.14.3
case "$(uname -s)-$(uname -m)" in
  Darwin-arm64)  ARCH=darwin-arm64; SHA=0360ce634a04c26a6b4fd957517987bb4f6c8950f63435ce3c5af2fcae5860c5 ;;
  Darwin-x86_64) ARCH=darwin-amd64; SHA=6d002b74d03b478547349cc10af89e007868596e5aa931816d45da9f544715a9 ;;
  *) echo "unsupported platform: $(uname -s)-$(uname -m)" >&2; exit 1 ;;
esac
NAME="sing-box-$VERSION-$ARCH"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
curl -fsSL -o "$TMP/$NAME.tar.gz" "https://github.com/SagerNet/sing-box/releases/download/v$VERSION/$NAME.tar.gz"
echo "$SHA  $TMP/$NAME.tar.gz" | shasum -a 256 -c - >/dev/null
tar -xzf "$TMP/$NAME.tar.gz" -C "$TMP"
mkdir -p "$ROOT/bin"
install -m 755 "$TMP/$NAME/sing-box" "$ROOT/bin/sing-box"
echo "sing-box $VERSION ($ARCH) -> $ROOT/bin/sing-box"
