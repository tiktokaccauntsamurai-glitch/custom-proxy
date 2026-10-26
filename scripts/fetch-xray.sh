#!/bin/sh
# Скачивает зафиксированную версию Xray-core в bin/ и проверяет SHA256 (macOS, Linux).
# Хеши сверены с официальными .dgst релиза.
# Xray нужен только для узлов с транспортом xhttp (его нет в sing-box): ARCHITECTURE.md §11.
set -eu
VERSION=26.3.27
# PLATFORM=Linux-aarch64 — скачать под другую платформу (сборка релиза: package-linux.sh).
PLATFORM="${PLATFORM:-$(uname -s)-$(uname -m)}"
case "$PLATFORM" in
  Darwin-arm64)  ARCH=macos-arm64-v8a; SHA=2e93a67e8aa1936ecefb307e120830fcbd4c643ab9b1c46a2d0838d5f8409eaf ;;
  Darwin-x86_64) ARCH=macos-64;        SHA=f5b0471d3459eff1b82e48af0aeac186abcc3298210070afbbbd8437a4e8b203 ;;
  Linux-x86_64)  ARCH=linux-64;        SHA=23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae ;;
  Linux-aarch64|Linux-arm64) ARCH=linux-arm64-v8a; SHA=4d30283ae614e3057f730f67cd088a42be6fdf91f8639d82cb69e48cde80413c ;;
  *) echo "unsupported platform: $PLATFORM" >&2; exit 1 ;;
esac
# shasum есть в macOS, в Linux обычно sha256sum.
sha256_check() { if command -v sha256sum >/dev/null 2>&1; then sha256sum -c - >/dev/null; else shasum -a 256 -c - >/dev/null; fi; }
NAME="Xray-$ARCH"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# BIN_DIR — куда положить ядро (по умолчанию <repo>/bin).
BIN_DIR="${BIN_DIR:-$ROOT/bin}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
curl -fsSL -o "$TMP/$NAME.zip" "https://github.com/XTLS/Xray-core/releases/download/v$VERSION/$NAME.zip"
echo "$SHA  $TMP/$NAME.zip" | sha256_check
# unzip есть не везде (минимальные Linux): запасной вариант — python3.
if command -v unzip >/dev/null 2>&1; then unzip -q "$TMP/$NAME.zip" -d "$TMP/x"; else python3 -m zipfile -e "$TMP/$NAME.zip" "$TMP/x"; fi
mkdir -p "$BIN_DIR"
install -m 755 "$TMP/x/xray" "$BIN_DIR/xray"
echo "xray $VERSION ($ARCH) -> $BIN_DIR/xray"
