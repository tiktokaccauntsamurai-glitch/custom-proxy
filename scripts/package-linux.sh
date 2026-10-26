#!/bin/sh
# Релиз под Linux: dist/cproxy-<версия>-linux-<arch>.tar.gz для x86_64 и aarch64 (папка — OUT_DIR=, по умолчанию dist/).
# В архиве: cproxy (статический musl), sing-box и xray (официальные, SHA256 проверяет fetch-*.sh), README.txt.
#
# Сначала собрать cproxy под обе архитектуры (на Windows — через zig, см. README «Build for Linux»):
#   cargo zigbuild --release -p cproxy --target x86_64-unknown-linux-musl
#   cargo zigbuild --release -p cproxy --target aarch64-unknown-linux-musl
# Затем запустить этот скрипт на Linux (или в WSL): sh scripts/package-linux.sh
# Архив собирается во временной папке Linux: на /mnt/c права на исполнение не сохраняются.
set -eu
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' "$ROOT/Cargo.toml" | head -n 1)"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
OUT="${OUT_DIR:-$ROOT/dist}"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"

for ARCH in x86_64 aarch64; do
  BIN="$ROOT/target/$ARCH-unknown-linux-musl/release/cproxy"
  if [ ! -f "$BIN" ]; then
    echo "skip $ARCH: $BIN not built" >&2
    continue
  fi
  NAME="cproxy-$VERSION-linux-$ARCH"
  DIR="$STAGE/$NAME"
  mkdir -p "$DIR"
  install -m 755 "$BIN" "$DIR/cproxy"
  PLATFORM="Linux-$ARCH" BIN_DIR="$DIR" sh "$ROOT/scripts/fetch-sing-box.sh"
  PLATFORM="Linux-$ARCH" BIN_DIR="$DIR" sh "$ROOT/scripts/fetch-xray.sh"
  cat > "$DIR/README.txt" <<EOF
cproxy $VERSION for Linux ($ARCH)

A private rule-based proxy that runs your Shadowrocket .conf.
Files: cproxy (this tool), sing-box 1.14.3 and Xray-core 26.3.27 (official builds).
Keep the three files in one folder.

START
  ./cproxy set rules /path/to/my.conf          your Shadowrocket config
  ./cproxy set connection /path/or/URL          optional: nodes (file or subscription URL)
  ./cproxy fetch                                download RULE-SET / GEOIP lists
  ./cproxy                                      run: HTTP + SOCKS5 on 127.0.0.1:7890

SYSTEM PROXY
  GNOME (Ubuntu, Fedora, Mint/Cinnamon) and KDE Plasma: switched on while cproxy runs,
  restored on exit. Elsewhere (servers, other desktops) use TUN or set
  export HTTP_PROXY=http://127.0.0.1:7890 HTTPS_PROXY=http://127.0.0.1:7890
  Off: ./cproxy set system-proxy off. Stuck after a crash: ./cproxy sysproxy off

TUN (all system traffic through the rules)
  ./cproxy run --tun        asks for the sudo password and keeps your settings
  ./cproxy set tun on       use TUN on every start

STOP
  Ctrl+C, or ./cproxy stop from another terminal (a TUN instance asks for sudo).

STATUS AND LOGS
  ./cproxy status           settings and the running instance
  ./cproxy set debug on     full log in ~/.local/share/cproxy/logs (off by default)

Data: \$XDG_DATA_HOME/cproxy or ~/.local/share/cproxy (override: CPROXY_HOME).
EOF
  tar -C "$STAGE" --owner=0 --group=0 -czf "$OUT/$NAME.tar.gz" "$NAME"
  (cd "$OUT" && sha256sum "$NAME.tar.gz" > "$NAME.tar.gz.sha256")
  echo "-> $OUT/$NAME.tar.gz"
done
