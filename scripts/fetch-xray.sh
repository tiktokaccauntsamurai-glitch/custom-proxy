#!/bin/sh
# Скачивает зафиксированную версию Xray-core в bin/ и проверяет SHA256 (macOS).
# Xray нужен только для узлов с транспортом xhttp (его нет в sing-box): ARCHITECTURE.md §11.
set -eu
VERSION=26.3.27
case "$(uname -s)-$(uname -m)" in
  Darwin-arm64)  ARCH=macos-arm64-v8a; SHA=2e93a67e8aa1936ecefb307e120830fcbd4c643ab9b1c46a2d0838d5f8409eaf ;;
  Darwin-x86_64) ARCH=macos-64;        SHA=f5b0471d3459eff1b82e48af0aeac186abcc3298210070afbbbd8437a4e8b203 ;;
  *) echo "unsupported platform: $(uname -s)-$(uname -m)" >&2; exit 1 ;;
esac
NAME="Xray-$ARCH"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
curl -fsSL -o "$TMP/$NAME.zip" "https://github.com/XTLS/Xray-core/releases/download/v$VERSION/$NAME.zip"
echo "$SHA  $TMP/$NAME.zip" | shasum -a 256 -c - >/dev/null
unzip -q "$TMP/$NAME.zip" -d "$TMP/x"
mkdir -p "$ROOT/bin"
install -m 755 "$TMP/x/xray" "$ROOT/bin/xray"
echo "xray $VERSION ($ARCH) -> $ROOT/bin/xray"
