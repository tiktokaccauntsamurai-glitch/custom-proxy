//! Узлы, которые не умеет официальный sing-box (транспорт `xhttp`), → второе ядро Xray-core.
//!
//! Схема (ARCHITECTURE.md §11): для каждого такого узла Xray слушает SOCKS5 на `127.0.0.1:<порт>`
//! со случайным логином/паролем (на каждый запуск), а sing-box получает вместо узла outbound
//! `socks` с тем же тегом. Группы, правила и fail-closed работают как с обычным узлом:
//! если Xray упал, соединения через узел обрываются, а не идут DIRECT.
//! Поля — Xray `infra/conf/xray.go`, `infra/conf/vless.go`, `infra/conf/transport_internet.go`
//! (`SplitHTTPConfig` = xhttpSettings, `TLSConfig`, `REALITYConfig`). Проверено на v26.3.27.
//! Вызывается из `lib.rs::generate` (шаг 1); конфиг Xray запускает `cli/src/main.rs::run`.

use core_model::Proxy;
use serde_json::{json, Value};

/// Нужен ли узлу Xray вместо sing-box.
pub fn needs_xray(p: &Proxy) -> bool {
    matches!(
        p.param(&["obfs", "network", "transport"]).map(str::to_ascii_lowercase).as_deref(),
        Some("xhttp") | Some("splithttp")
    )
}

/// Конфиг Xray: по паре inbound(socks)/outbound на узел, связанной правилом routing.
pub struct Config {
    inbounds: Vec<Value>,
    outbounds: Vec<Value>,
    rules: Vec<Value>,
}

impl Config {
    pub fn new() -> Self {
        Config { inbounds: Vec::new(), outbounds: Vec::new(), rules: Vec::new() }
    }

    pub fn is_empty(&self) -> bool {
        self.outbounds.is_empty()
    }

    /// Добавляет узел; возвращает outbound `socks` для sing-box с тем же тегом.
    pub fn add(&mut self, p: &Proxy, port: u16, warnings: &mut Vec<String>) -> Result<Value, String> {
        let i = self.outbounds.len();
        let tag = format!("node-{i}");
        let mut out = outbound(p, warnings)?;
        out["tag"] = tag.clone().into();
        let (user, pass) = (format!("cproxy{i}"), random_token());
        // sniffing с routeOnly=false: после `resolve` sing-box набирает узел по IP (route/conn.go:103,
        // ARCHITECTURE.md §8), а Xray возвращает домен из SNI/Host/QUIC, и узел получает домен, как
        // в Shadowrocket. Цена: ~0.2 с на протоколах, где первым говорит сервер (SSH, SMTP).
        self.inbounds.push(json!({
            "tag": tag, "listen": "127.0.0.1", "port": port, "protocol": "socks",
            "settings": {"auth": "password", "accounts": [{"user": user, "pass": pass}], "udp": true},
            "sniffing": {"enabled": true, "destOverride": ["http", "tls", "quic"], "routeOnly": false},
        }));
        self.outbounds.push(out);
        self.rules.push(json!({"inboundTag": [tag], "outboundTag": tag}));
        Ok(json!({
            "type": "socks", "tag": p.name, "server": "127.0.0.1", "server_port": port,
            "version": "5", "username": user, "password": pass,
        }))
    }

    /// `log_level` — уровень cproxy (trace..error); Xray: debug|info|warning|error|none.
    pub fn build(self, log_level: Option<&str>) -> Value {
        let level = match log_level {
            Some("trace") | Some("debug") => "debug",
            Some("info") => "info",
            Some("warn") => "warning",
            Some(_) => "error",
            None => "none",
        };
        json!({
            "log": {"loglevel": level, "access": if level == "debug" || level == "info" { "" } else { "none" }},
            "inbounds": self.inbounds,
            "outbounds": self.outbounds,
            "routing": {"rules": self.rules},
        })
    }
}

/// Случайная строка без внешних зависимостей: `RandomState` засевается из ОС.
fn random_token() -> String {
    use std::hash::{BuildHasher, Hasher};
    let mut s = String::new();
    for _ in 0..2 {
        let mut h = std::collections::hash_map::RandomState::new().build_hasher();
        h.write_usize(s.len());
        s += &format!("{:016x}", h.finish());
    }
    s
}

fn outbound(p: &Proxy, warnings: &mut Vec<String>) -> Result<Value, String> {
    let secret = |keys: &[&str]| p.param(keys).filter(|s| !s.is_empty()).ok_or_else(|| format!("missing `{}`", keys[0]));
    let (protocol, settings) = match p.kind.as_str() {
        "vless" => {
            let mut user = json!({"id": secret(&["password", "username", "uuid"])?, "encryption": "none"});
            if let Some(flow) = p.param(&["flow"]).filter(|f| !f.is_empty()) {
                user["flow"] = flow.into();
            }
            ("vless", json!({"vnext": [{"address": p.server, "port": p.port, "users": [user]}]}))
        }
        "vmess" => {
            let user = json!({
                "id": secret(&["password", "username", "uuid"])?,
                "security": p.param(&["method", "cipher", "security"]).unwrap_or("auto"),
            });
            ("vmess", json!({"vnext": [{"address": p.server, "port": p.port, "users": [user]}]}))
        }
        "trojan" => ("trojan", json!({"servers": [{"address": p.server, "port": p.port, "password": secret(&["password"])?}]})),
        other => return Err(format!("`{other}` over xhttp is not supported (vless/vmess/trojan only)")),
    };
    let mut xhttp = json!({"path": p.param(&["path", "obfs-uri", "obfs-path"]).unwrap_or("/")});
    let host = p.param(&["obfs-host", "host"]);
    if let Some(h) = host {
        xhttp["host"] = h.into();
    }
    if let Some(m) = p.param(&["mode", "xhttp-mode"]) {
        xhttp["mode"] = m.into();
    }
    if let Some(extra) = p.param(&["xhttp-extra", "extra"]) {
        xhttp["extra"] = serde_json::from_str(extra).map_err(|e| format!("bad xhttp extra: {e}"))?;
    }
    // XMUX по умолчанию. Xray v26 без xmux ставит maxConcurrency=1 (infra/conf/transport_internet.go:
    // `c.Xmux == (XmuxConfig{})`) — новое TLS-соединение на каждую сессию; на сервере пользователя
    // это давало ~50% зависаний по 19 с (отдельный xray: 11/20). `16-32` (прежнее значение Xray и Hiddify)
    // — 20/20. Явный xmux узла (в extra) не трогаем.
    if xhttp["extra"].get("xmux").is_none() {
        xhttp["xmux"] = json!({"maxConcurrency": "16-32"});
    }
    let mut stream = json!({"network": "xhttp", "xhttpSettings": xhttp});
    let sni = p.param(&["peer", "sni", "servername", "tls-host", "tls-name"]).or(host);
    let fp = p.param(&["fp", "client-fingerprint", "utls"]);
    if let Some(pbk) = p.param(&["pbk", "publicKey", "public-key", "reality-public-key"]) {
        stream["security"] = "reality".into();
        stream["realitySettings"] = json!({
            "serverName": sni.unwrap_or(&p.server), "fingerprint": fp.unwrap_or("chrome"), "publicKey": pbk,
            "shortId": p.param(&["sid", "shortId", "short-id", "reality-short-id"]).unwrap_or(""),
        });
    } else if p.flag(&["tls", "over-tls"]) || p.kind == "trojan" {
        let mut t = json!({"serverName": sni.unwrap_or(&p.server)});
        if let Some(a) = p.param(&["alpn"]) {
            t["alpn"] = json!(a.split(['|', ';', ' ']).filter(|s| !s.is_empty()).collect::<Vec<_>>());
        }
        if let Some(fp) = fp {
            t["fingerprint"] = fp.into();
        }
        // Xray ≥ 26: allowInsecure удалён (transport_internet.go::TLSConfig.Build) — проверку не отключаем.
        if p.flag(&["allowInsecure", "skip-cert-verify", "insecure"]) {
            warnings.push(format!("node `{}`: skip-cert-verify is not supported by Xray ≥ 26; certificate is verified", p.name));
        }
        stream["security"] = "tls".into();
        stream["tlsSettings"] = t;
    }
    Ok(json!({"protocol": protocol, "settings": settings, "streamSettings": stream}))
}
