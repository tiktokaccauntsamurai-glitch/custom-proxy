# cproxy

A small, private, rule-based proxy for **Windows, macOS and Linux** that runs your **Shadowrocket (iOS) `.conf`** on a desktop.

cproxy is a command-line wrapper written in Rust. It does not implement network protocols itself. It translates your Shadowrocket rules into a configuration for the official [sing-box](https://github.com/SagerNet/sing-box) core and runs that core as a child process. Nodes that use the `xhttp` transport, which sing-box does not support, are handed to the official [Xray-core](https://github.com/XTLS/Xray-core).

```
apps ──► 127.0.0.1:7890 (HTTP + SOCKS5) ──► sing-box ──► rules ──► DIRECT / node / REJECT
         or TUN (all system traffic)                         └──► Xray-core (xhttp nodes)
```

> Status: `0.1.0-dev`. Tested on Windows 11. Linux builds are tested on Ubuntu 24.04 (proxy mode); Linux TUN and the GNOME/KDE system proxy are not tested on real hardware yet. macOS is supported in the code but has not been tested yet.

---

## Contents

- [Features](#features)
- [Privacy and security](#privacy-and-security)
- [Requirements](#requirements)
- [Build](#build)
- [Quick start](#quick-start)
- [Two configs: rules and connection](#two-configs-rules-and-connection)
- [Modes: system proxy and TUN](#modes-system-proxy-and-tun)
- [Commands](#commands)
- [Options](#options)
- [Logs and debugging](#logs-and-debugging)
- [What is supported from Shadowrocket](#what-is-supported-from-shadowrocket)
- [Known limitations](#known-limitations)
- [Data locations](#data-locations)
- [Project layout](#project-layout)
- [Development](#development)
- [License](#license)

---

## Features

- **Your Shadowrocket config as is.** Reads `[General]`, `[Rule]`, `[Proxy]`, `[Proxy Group]` and `[Host]`. Rule order and matching follow Shadowrocket semantics. The parser is lossless: reading and writing a `.conf` returns it byte for byte, comments and unknown sections included.
- **Any node source.** The connection can be a file or a subscription URL in any of these formats:
  - share links `vless://`, `vmess://`, `trojan://`, `ss://`, `hy2://`, `tuic://`, `socks://`, `anytls://`, `wg://`;
  - base64 subscriptions;
  - Clash / Mihomo YAML;
  - sing-box JSON;
  - Xray JSON;
  - the `[Proxy]` section of a Shadowrocket `.conf`.
- **Official cores only.** sing-box 1.14.3 and Xray-core 26.3.27, downloaded by scripts with pinned SHA256 hashes. No custom builds.
- **Local HTTP + SOCKS5** on `127.0.0.1:7890` (one port for both protocols), or on the port from your `.conf`.
- **System proxy** is switched on automatically while cproxy runs and is always restored afterwards: Windows, macOS, and GNOME / KDE Plasma on Linux (see [Modes](#modes-system-proxy-and-tun)).
- **TUN mode** captures all system traffic, including apps that ignore proxy settings. It uses fake-IP DNS, so nodes receive domain names, not IP addresses.
- **Supervisor.** Restarts a crashed core and ties both cores to cproxy, so closing the window stops everything (Windows Job Object, Linux `PR_SET_PDEATHSIG`). `cproxy status` and `cproxy stop` work from another terminal.
- **Drag and drop.** Drop a `.conf` or a node file onto `cproxy.exe`: it is saved as rules or connection and started.
- **Small.** One `cproxy` binary of about 3 MB plus the two cores. On Linux it is a static musl binary that runs on any distribution.

## Privacy and security

- **No telemetry.** cproxy itself makes network requests only to the rule lists and subscription URLs from your configs, and only on `fetch`/`run`.
- **Secrets never touch the disk.** The generated configurations, which contain node passwords and keys, are passed to sing-box and Xray via **stdin** (`sing-box run -c stdin`, `xray run -c stdin:`). Subscription contents are kept in memory only; `settings.json` stores just the URL.
- **Logs are off by default.** With debug logging on, passwords, UUIDs, keys and subscription tokens are replaced with `***`, and subscription URLs are written as `https://host/***`.
- **Fail-closed routing.** A rule that points to a missing policy or an empty group becomes `REJECT`, never `DIRECT`. If Xray stops, connections through its nodes fail instead of leaking directly.
- **Encrypted DNS by default.** If the `.conf` sets no `dns-server`, DNS goes over DoH to `1.1.1.1` (by IP, without the system resolver).
- **Local only by default.** The proxy listens on `127.0.0.1`. `--lan` opens it to the local network **without a password**, so use it only on trusted networks.
- **The Xray bridge is protected.** Each run, Xray's local SOCKS inbound gets a random login and password, so other local programs cannot use it as an open proxy.
- **The system proxy is always restored.** The previous settings are saved to `sysproxy-backup.json` *before* any change and restored on exit, on Ctrl+C and on window close. After a crash, `cproxy sysproxy off` restores them manually.

## Requirements

- Windows 10/11 x64, macOS (Intel / Apple Silicon) or Linux x86_64 / aarch64.
- To build: a stable [Rust](https://rustup.rs) toolchain (edition 2021).
- To fetch the cores: PowerShell (Windows) or `sh` + `curl` + `sha256sum`/`shasum` + `unzip`/`python3` (macOS, Linux).
- TUN mode: administrator rights (Windows asks via UAC) or root (Linux and macOS ask for the `sudo` password).

## Build

```powershell
# Windows
scripts\fetch-sing-box.ps1        # sing-box 1.14.3  -> bin\
scripts\fetch-xray.ps1            # Xray-core 26.3.27 -> bin\  (only needed for xhttp nodes)
cargo build --release -p cproxy   # -> target\release\cproxy.exe
```

```bash
# macOS / Linux
scripts/fetch-sing-box.sh
scripts/fetch-xray.sh
cargo build --release -p cproxy   # -> target/release/cproxy
```

### Linux release archives

`scripts/package-linux.sh` builds `dist/cproxy-<version>-linux-{x86_64,aarch64}.tar.gz`: a static `cproxy` plus the official `sing-box` and `xray` for that architecture, with a `.sha256` file next to each archive. Build `cproxy` for both targets first. From Windows this works through [zig](https://ziglang.org):

```powershell
rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl
pip install ziglang
cargo install cargo-zigbuild
$env:CARGO_ZIGBUILD_ZIG_PATH = "<python site-packages>\ziglang\zig.exe"
cargo zigbuild --release -p cproxy --target x86_64-unknown-linux-musl
cargo zigbuild --release -p cproxy --target aarch64-unknown-linux-musl
```

Then run `sh scripts/package-linux.sh` on Linux or in WSL (`OUT_DIR=<dir>` puts the archives elsewhere). The fetch scripts accept `PLATFORM=Linux-aarch64` and `BIN_DIR=<dir>` to download cores for another platform.

The fetch scripts download the official release archives from GitHub and stop if the SHA256 hash does not match the pinned value.

cproxy looks for `sing-box` and `xray` in this order: the `--sing-box` / `--xray` flags, the `CPROXY_SING_BOX` / `CPROXY_XRAY` environment variables, next to the `cproxy` binary, `<repo>/bin`, `./bin`, then `PATH`. To ship it, put `cproxy.exe`, `sing-box.exe` and `xray.exe` in one folder.

## Quick start

```powershell
cproxy set rules "C:\path\to\my.conf"          # your Shadowrocket config
cproxy set connection "https://example.com/sub" # optional: nodes from a file or subscription
cproxy fetch                                    # download RULE-SET / DOMAIN-SET / GEOIP lists
cproxy                                          # start with the saved settings
```

While cproxy runs, the system proxy points at it, so browsers work without extra setup. For terminal programs:

```powershell
$env:HTTP_PROXY  = "http://127.0.0.1:7890"
$env:HTTPS_PROXY = "http://127.0.0.1:7890"
# SOCKS5 is available on the same port: socks5h://127.0.0.1:7890
```

Stop it with Ctrl+C, by closing the window, or with `cproxy stop` from another terminal.

On Linux, unpack the archive and run `./cproxy` from that folder; the cores are found next to it.

You can also run a config once without saving anything:

```powershell
cproxy run my.conf --port 1080
```

The port comes from `[General]` in the `.conf` when it is set there:

```ini
[General]
http-listen = 127.0.0.1:7890      # or just 7890
socks5-listen = 127.0.0.1:7891    # optional; without it SOCKS5 shares the HTTP port
```

`--port N` and `--lan` override these values.

## Two configs: rules and connection

cproxy keeps two independent configs, both saved in `settings.json`:

| setting | what it is | example |
|---|---|---|
| `rules` | a Shadowrocket `.conf`: rules, groups, DNS, port | `cproxy set rules my.conf` |
| `connection` | where nodes come from: a file or a subscription URL | `cproxy set connection nodes.txt` |

`nodes` chooses which nodes are used:

| mode | nodes used |
|---|---|
| `auto` (default) | `connection` if set, otherwise `[Proxy]` from the rules |
| `connection` | only from `connection` |
| `rules` | only `[Proxy]` from the rules |
| `both` | both lists together |

This lets you use a public rule set (for example, one of the [LOWERTOP/Shadowrocket](https://github.com/LOWERTOP/Shadowrocket) configs) with nodes from your own provider. Groups with `policy-regex-filter` pick from whichever nodes are in use.

## Modes: system proxy and TUN

**System proxy (default).** cproxy sets the OS proxy to `127.0.0.1:<port>` while it runs and restores the previous value on exit. Turn it off with `cproxy set system-proxy off` or `--no-system-proxy` for a single run.

On Linux there is no single system proxy, so cproxy sets every one it finds:

- **GNOME** and desktops built on it (Ubuntu, Fedora Workstation, Cinnamon, Budgie): `gsettings`, schema `org.gnome.system.proxy`. Requires a D-Bus session.
- **KDE Plasma 5/6**: `kioslaverc` via `kwriteconfig`, then KIO is told to reload.

On servers and other desktops cproxy prints a hint instead: use TUN, or `export HTTP_PROXY=http://127.0.0.1:7890 HTTPS_PROXY=http://127.0.0.1:7890`. The proxy keeps running either way.

cproxy warns at start-up if `HTTP_PROXY`, `HTTPS_PROXY` or `ALL_PROXY` in your environment point somewhere else, because such programs would bypass it.

**TUN.** `cproxy run --tun` (or `cproxy set tun on`) creates a virtual network adapter and routes all system traffic through the rules.

- Needs administrator rights. Without them, cproxy restarts itself with the same arguments: through UAC in a new window on Windows, through `sudo` in the same terminal on Linux and macOS. Under `sudo` it keeps using your settings and gives the data folder back to your user on exit. `cproxy stop` from your user asks for `sudo` to stop it.
- DNS uses fake IPs from `198.18.0.0/15`, so sing-box knows the domain of every connection and nodes receive domains.
- Some names always get real addresses: local names (`*.lan`, `*.local`, `*.home.arpa`), time servers, STUN and Windows connectivity checks. Add your own with `always-real-ip` in `[General]`; `always-real-ip = *` turns fake IPs off.
- The system proxy is not touched while TUN is on.
- The IPs of Xray node servers are excluded from TUN, so the Xray connection itself never loops back into the tunnel.

## Commands

| command | what it does |
|---|---|
| `cproxy` | start with the saved settings |
| `cproxy <file>` | save a dropped file as rules or connection, then start |
| `cproxy set rules <file.conf\|none>` | save the path to the rules |
| `cproxy set connection <file\|URL\|none>` | save the node source |
| `cproxy set nodes auto\|connection\|rules\|both` | choose which nodes to use |
| `cproxy set system-proxy on\|off` | switch the OS proxy on while running (default on) |
| `cproxy set tun on\|off` | TUN mode: all system traffic (admin / UAC) |
| `cproxy set debug on\|off` | full log in `<data>/logs` on every run |
| `cproxy status` | saved settings and the running instance (PIDs, port, log file) |
| `cproxy stop` | stop the running instance (restores the system proxy) |
| `cproxy sysproxy status\|off` | show the OS proxy / restore the previous one |
| `cproxy check [rules.conf] [opts]` | parse configs, count nodes/groups/rules, print warnings |
| `cproxy fetch [rules.conf] [--via URL] [--force]` | download RULE-SET / DOMAIN-SET / GEOIP lists into the cache |
| `cproxy gen [rules.conf] [-o FILE] [opts]` | print the sing-box config (**contains secrets**) |
| `cproxy run [rules.conf] [opts]` | start the local proxy |

`cproxy fetch --via http://127.0.0.1:7890` updates the lists through an already running proxy.

## Options

Options apply to a single run and override the saved settings.

| option | meaning |
|---|---|
| `--nodes FILE\|URL` | node source for this run |
| `--nodes-mode M` | `auto\|connection\|rules\|both` for this run |
| `--system-proxy` / `--no-system-proxy` | switch the OS proxy for this run |
| `--tun` / `--no-tun` | TUN mode for this run |
| `--port N` | port for apps (HTTP + SOCKS5) |
| `--lan` | listen on `0.0.0.0` (local network, no password) |
| `--debug` / `--no-debug` | full log for this run |
| `--log LEVEL` | exact log level: `off\|error\|warn\|info\|debug\|trace` |
| `-v`, `--verbose` | also print the detailed log to the console |
| `--via URL` | proxy used by `fetch` and subscription downloads |
| `--sing-box PATH`, `--xray PATH` | use specific core binaries |
| `-o FILE` | output file for `gen` |
| `--force` | `fetch`: download again even if cached |

## Logs and debugging

There is one build. Logging is chosen at launch:

| how | effect |
|---|---|
| default | no log files |
| `--debug` | full trace log for this run |
| `cproxy set debug on` | full trace log on every run (useful when starting by double-click) |
| `--no-debug` | no log for this run, even with `set debug on` |
| `--log LEVEL` | exact level; takes priority over everything above |
| `CPROXY_LOG=LEVEL` | the same through the environment |

Priority: `--log` > `--debug`/`--no-debug` > `CPROXY_LOG` > `set debug`.

A debug log is one file per command in `<data>/logs/` (the last 20 are kept). It contains every step from the command line to each connection made by sing-box and Xray. Every routing decision is annotated with the `.conf` line that caused it:

```
router: match[48] domain_suffix=ya.ru => route(DIRECT)  ⇐ [Rule] line 134: DOMAIN-SUFFIX,ya.ru,DIRECT
```

To debug a problem, start with the newest log. `cproxy status` prints its path.

Trace logging costs CPU and disk I/O under heavy traffic. Keep it off for everyday use.

## What is supported from Shadowrocket

**Rules:** `DOMAIN`, `DOMAIN-SUFFIX`, `DOMAIN-KEYWORD`, `DOMAIN-WILDCARD`, `IP-CIDR`, `IP-CIDR6` (with `no-resolve`), `SRC-IP`, `DST-PORT`, `SRC-PORT`, `PROCESS-NAME`, `PROTOCOL`, `GEOIP` (country, `LAN`), `RULE-SET`, `DOMAIN-SET`, nested `AND` / `OR` / `NOT`, `FINAL`.

**Policies:** `DIRECT`, `PROXY`, `REJECT`, `REJECT-DROP`, `REJECT-NO-DROP`, any group or node name (case-insensitive, an exact match wins).

**Groups:** `select`, `url-test` (`url`, `interval`, `tolerance`), `policy-regex-filter`. `fallback`, `load-balance` and `random` run as `url-test`, with a warning.

**Nodes:** Shadowsocks (incl. `obfs` and `v2ray-plugin`), VMess, VLESS (incl. Vision and REALITY), Trojan, Hysteria, Hysteria2, TUIC, AnyTLS, WireGuard, Snell (v4/v6), SSH, SOCKS5, HTTP(S). `socks5-tls` and Juicity nodes are skipped with a warning. Transports: TCP, WebSocket, gRPC, HTTP/2, HTTPUpgrade, and `xhttp` through Xray. TLS options: SNI, ALPN, uTLS fingerprint, `skip-cert-verify`.

**DNS:** `dns-server` (DoH, DoT, plain, `system`), `[Host]` mappings, fake IP in TUN with `always-real-ip`.

Anything that cproxy reads but cannot execute is reported as a **warning** by `cproxy check` and at start-up. It is never dropped silently.

## Known limitations

- **No MITM yet:** `[URL Rewrite]`, `[MITM]`, `[Script]`, `USER-AGENT` and `URL-REGEX` are kept in the file but not executed. `REJECT-200` / `REJECT-IMG` and similar act as plain `REJECT`.
- `IP-ASN` rules are not supported.
- Subscriptions inside groups (`use=true`) are not supported yet; set the subscription as the `connection` instead.
- When a connection reaches an IP-based rule (such as `GEOIP`), sing-box resolves the domain to check it and then sends the **IP** to sing-box-native nodes. `xhttp` nodes are not affected: Xray restores the domain from TLS SNI / HTTP Host.
- macOS has not been tested yet. On Linux, TUN and the GNOME/KDE system proxy have not been tested on real hardware yet.

## Data locations

| OS | directory |
|---|---|
| Windows | `%APPDATA%\cproxy` |
| macOS | `~/Library/Application Support/cproxy` |
| Linux | `$XDG_DATA_HOME/cproxy`, by default `~/.local/share/cproxy` |

Override it with the `CPROXY_HOME` environment variable. It contains `settings.json`, `run.json` (the running instance), `sysproxy-backup.json` (only while the OS proxy is changed), the rule-list cache and `logs/`.

## Project layout

```
crates/core-model        data model: Rule, Matcher, Proxy, ProxyGroup
crates/fmt-shadowrocket  lossless .conf parser and writer
crates/fmt-nodes         node sources: share links, base64, Clash YAML, sing-box / Xray JSON
crates/singbox-gen       .conf + nodes -> sing-box JSON (and an Xray config for xhttp nodes)
crates/supervisor        starts, restarts and stops the cores (Job Object / PDEATHSIG / signals)
crates/cli               the `cproxy` binary: commands, settings, system proxy, TUN elevation, logging
scripts/                 fetch the pinned sing-box and Xray releases with SHA256 checks; package-linux.sh
```

Code comments are in Russian.

## Development

```powershell
cargo test --workspace
```

If `bin/` contains the cores, some tests also run the real `sing-box check` and `xray run -test` against generated configs. For experiments, set `CPROXY_HOME` to a scratch directory, so your real settings are not touched.

## License

[MIT](LICENSE)
