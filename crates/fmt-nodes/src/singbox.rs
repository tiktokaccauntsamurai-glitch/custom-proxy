//! sing-box JSON (`outbounds[]` / `endpoints[]`) → `Proxy` с ключами Shadowrocket.
//!
//! Обратное отображение к `singbox-gen/src/outbound.rs`: ключи берутся те, что он читает первыми
//! (`password`, `sni`, `skip-cert-verify`, `obfs`, `path`, `host`, ...), чтобы узел прошёл туда и обратно.
//! Поля — sing-box `option/<протокол>.go`, `option/tls.go`, `option/v2ray_transport.go`.
//! Транспорт `xhttp` в официальном sing-box отсутствует (встречается в форках и экспортах панелей):
//! узел получает `obfs=xhttp`, исполняет его Xray (`singbox-gen/src/xray.rs`, ARCHITECTURE.md §11).
//! Неизвестные поля → warning (узел остаётся).

use core_model::{Node, Proxy};
use serde_json::{Map, Value};

use crate::Parsed;

/// Служебные outbound — не узлы.
const SERVICE: &[&str] = &["direct", "block", "dns", "selector", "urltest"];

pub fn parse(v: &Value, label: &str) -> Parsed {
    let mut nodes = Vec::new();
    let mut warnings = Vec::new();
    let items = ["outbounds", "endpoints"].iter().flat_map(|k| v[k].as_array().into_iter().flatten());
    for (i, o) in items.enumerate() {
        let tag = o["tag"].as_str().unwrap_or("").to_string();
        let kind = o["type"].as_str().unwrap_or("");
        if SERVICE.contains(&kind) {
            if matches!(kind, "selector" | "urltest") {
                warnings.push(format!("{label} #{i} `{tag}`: groups from sing-box JSON are ignored (use [Proxy Group] in rules)"));
            }
            continue;
        }
        let Some(o) = o.as_object() else { continue };
        let mut unknown = Vec::new();
        match convert(o, &mut unknown) {
            Ok(mut proxy) => {
                if proxy.name.is_empty() {
                    proxy.name = format!("{kind} {}", proxy.server);
                }
                if !unknown.is_empty() {
                    warnings.push(format!("{label} #{i} `{}`: ignored fields {unknown:?}", proxy.name));
                }
                log::debug!(target: "nodes", "{label} #{i} `{}`: {} {}:{}", proxy.name, proxy.kind, proxy.server, proxy.port);
                nodes.push(Node { origin: format!("{label} #{i} (sing-box JSON)"), proxy });
            }
            Err(e) => warnings.push(format!("{label} #{i} `{tag}`: {e}; node skipped")),
        }
    }
    Parsed { format: "sing-box JSON", nodes, warnings }
}

struct P {
    params: Vec<(String, String)>,
}

impl P {
    fn set(&mut self, k: &str, v: impl Into<String>) {
        self.params.push((k.into(), v.into()));
    }
    fn opt(&mut self, k: &str, v: Option<&Value>) {
        if let Some(s) = v.and_then(scalar) {
            self.set(k, s);
        }
    }
}

fn scalar(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn convert(o: &Map<String, Value>, unknown: &mut Vec<String>) -> Result<Proxy, String> {
    let kind = o["type"].as_str().unwrap_or("");
    let mut p = P { params: Vec::new() };
    // Поля, которые разобраны (остальные → warning).
    let mut used = vec!["type", "tag", "server", "server_port"];
    let mut kind_out = kind.to_string();
    match kind {
        "shadowsocks" => {
            kind_out = "ss".into();
            used.extend(["method", "password", "plugin", "plugin_opts"]);
            p.opt("method", o.get("method"));
            p.opt("password", o.get("password"));
            if let Some(plugin) = o.get("plugin").and_then(Value::as_str) {
                let opts = o.get("plugin_opts").and_then(Value::as_str).unwrap_or("");
                plugin_to_params(plugin, opts, &mut p)?;
            }
        }
        "vmess" => {
            used.extend(["uuid", "security", "alter_id"]);
            p.opt("password", o.get("uuid"));
            p.opt("method", o.get("security"));
            p.opt("alterId", o.get("alter_id"));
        }
        "vless" => {
            used.extend(["uuid", "flow", "packet_encoding"]);
            p.opt("password", o.get("uuid"));
            p.opt("flow", o.get("flow"));
            p.opt("packet-encoding", o.get("packet_encoding"));
        }
        "trojan" | "anytls" => {
            used.push("password");
            p.opt("password", o.get("password"));
        }
        "hysteria2" => {
            used.extend(["password", "obfs", "up_mbps", "down_mbps"]);
            p.opt("password", o.get("password"));
            if let Some(ob) = o.get("obfs") {
                p.opt("obfs-password", ob.get("password"));
            }
            p.opt("upmbps", o.get("up_mbps"));
            p.opt("downmbps", o.get("down_mbps"));
        }
        "hysteria" => {
            used.extend(["auth_str", "obfs", "up_mbps", "down_mbps"]);
            p.opt("auth", o.get("auth_str"));
            p.opt("obfsParam", o.get("obfs"));
            p.opt("upmbps", o.get("up_mbps"));
            p.opt("downmbps", o.get("down_mbps"));
        }
        "tuic" => {
            used.extend(["uuid", "password", "congestion_control"]);
            p.opt("uuid", o.get("uuid"));
            p.opt("password", o.get("password"));
            p.opt("congestion-controller", o.get("congestion_control"));
        }
        "http" | "socks" => {
            used.extend(["username", "password", "version"]);
            p.opt("username", o.get("username"));
            p.opt("password", o.get("password"));
            if kind == "socks" {
                kind_out = "socks5".into();
            } else if o.get("tls").and_then(|t| t.get("enabled")).and_then(Value::as_bool) == Some(true) {
                kind_out = "https".into();
            }
        }
        "ssh" => {
            used.extend(["user", "password", "private_key_path"]);
            p.opt("username", o.get("user"));
            p.opt("password", o.get("password"));
            p.opt("private-key", o.get("private_key_path"));
        }
        "wireguard" => return wireguard(o, unknown),
        other => return Err(format!("unsupported type `{other}`")),
    }
    if o.get("tcp_fast_open").and_then(Value::as_bool) == Some(true) {
        p.set("tfo", "true");
    }
    used.push("tcp_fast_open");
    if let Some(t) = o.get("tls") {
        used.push("tls");
        tls(t, &mut p, unknown);
    }
    if let Some(t) = o.get("transport") {
        used.push("transport");
        transport(t, &mut p, unknown)?;
    }
    unknown.extend(o.keys().filter(|k| !used.contains(&k.as_str())).cloned());
    Ok(Proxy {
        name: o.get("tag").and_then(Value::as_str).unwrap_or("").to_string(),
        kind: kind_out,
        server: o.get("server").and_then(Value::as_str).ok_or("missing `server`")?.to_string(),
        port: o.get("server_port").and_then(Value::as_u64).and_then(|p| u16::try_from(p).ok()).ok_or("missing `server_port`")?,
        args: Vec::new(),
        params: p.params,
    })
}

fn tls(t: &Value, p: &mut P, unknown: &mut Vec<String>) {
    if t.get("enabled").and_then(Value::as_bool) != Some(true) {
        return;
    }
    p.set("tls", "true");
    p.opt("sni", t.get("server_name"));
    if t.get("insecure").and_then(Value::as_bool) == Some(true) {
        p.set("skip-cert-verify", "true");
    }
    if let Some(a) = t.get("alpn").and_then(Value::as_array) {
        let alpn: Vec<&str> = a.iter().filter_map(Value::as_str).collect();
        p.set("alpn", alpn.join("|"));
    }
    if let Some(u) = t.get("utls").filter(|u| u.get("enabled").and_then(Value::as_bool) == Some(true)) {
        p.set("fp", u.get("fingerprint").and_then(Value::as_str).unwrap_or("chrome"));
    }
    if let Some(r) = t.get("reality").filter(|r| r.get("enabled").and_then(Value::as_bool) == Some(true)) {
        p.opt("pbk", r.get("public_key"));
        p.opt("sid", r.get("short_id"));
    }
    if let Some(m) = t.as_object() {
        let known = ["enabled", "server_name", "insecure", "alpn", "utls", "reality"];
        unknown.extend(m.keys().filter(|k| !known.contains(&k.as_str())).map(|k| format!("tls.{k}")));
    }
}

fn transport(t: &Value, p: &mut P, unknown: &mut Vec<String>) -> Result<(), String> {
    let kind = t.get("type").and_then(Value::as_str).unwrap_or("");
    let mut known = vec!["type", "path", "host"];
    match kind {
        "ws" => {
            p.set("obfs", "websocket");
            p.opt("path", t.get("path"));
            p.opt("obfs-host", t.get("headers").and_then(|h| h.get("Host")));
            known.extend(["headers", "max_early_data", "early_data_header_name"]);
        }
        "grpc" => {
            p.set("obfs", "grpc");
            p.opt("grpc-service-name", t.get("service_name"));
            known.push("service_name");
        }
        "http" => {
            p.set("obfs", "h2");
            p.opt("path", t.get("path"));
            p.opt("obfs-host", t.get("host").and_then(|h| h.as_array().and_then(|a| a.first()).or(Some(h))));
        }
        "httpupgrade" => {
            p.set("obfs", "httpupgrade");
            p.opt("path", t.get("path"));
            p.opt("obfs-host", t.get("host"));
        }
        // Не официальный sing-box: поля как в Xray `xhttpSettings` (host, path, mode, extra).
        "xhttp" => {
            p.set("obfs", "xhttp");
            p.opt("path", t.get("path"));
            p.opt("obfs-host", t.get("host"));
            p.opt("mode", t.get("mode"));
            if let Some(extra) = t.get("extra").filter(|e| e.is_object()) {
                p.set("xhttp-extra", extra.to_string());
            }
            known.extend(["mode", "extra"]);
        }
        "quic" => p.set("obfs", "quic"),
        other => return Err(format!("unsupported transport `{other}`")),
    }
    if let Some(m) = t.as_object() {
        unknown.extend(m.keys().filter(|k| !known.contains(&k.as_str())).map(|k| format!("transport.{k}")));
    }
    Ok(())
}

/// `plugin` + `plugin_opts` sing-box (формат SIP003) → `obfs=` Shadowrocket.
fn plugin_to_params(plugin: &str, opts: &str, p: &mut P) -> Result<(), String> {
    let kv: Vec<(&str, &str)> = opts.split(';').map(|s| s.split_once('=').unwrap_or((s, ""))).collect();
    let get = |k: &str| kv.iter().find(|(a, _)| *a == k).map(|(_, v)| *v);
    match plugin {
        "obfs-local" | "simple-obfs" => {
            p.set("obfs", get("obfs").unwrap_or("http"));
            if let Some(h) = get("obfs-host") {
                p.set("obfs-host", h);
            }
        }
        "v2ray-plugin" => {
            p.set("obfs", "websocket");
            if let Some(h) = get("host") {
                p.set("obfs-host", h);
            }
            if let Some(path) = get("path") {
                p.set("path", path);
            }
            if kv.iter().any(|(k, _)| *k == "tls") {
                p.set("tls", "true");
            }
        }
        other => return Err(format!("unsupported ss plugin `{other}`")),
    }
    Ok(())
}

fn wireguard(o: &Map<String, Value>, unknown: &mut Vec<String>) -> Result<Proxy, String> {
    let peer = o.get("peers").and_then(|p| p.get(0)).ok_or("wireguard without peers")?;
    let mut p = P { params: Vec::new() };
    p.opt("privateKey", o.get("private_key"));
    p.opt("publicKey", peer.get("public_key"));
    p.opt("preSharedKey", peer.get("pre_shared_key"));
    p.opt("keepalive", peer.get("persistent_keepalive_interval"));
    p.opt("mtu", o.get("mtu"));
    for a in o.get("address").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str) {
        p.set(if a.contains(':') { "ipv6" } else { "ip" }, a);
    }
    if let Some(r) = peer.get("reserved").and_then(Value::as_array) {
        let r: Vec<String> = r.iter().filter_map(scalar).collect();
        p.set("reserved", r.join("/"));
    }
    let known = ["type", "tag", "address", "private_key", "peers", "mtu"];
    unknown.extend(o.keys().filter(|k| !known.contains(&k.as_str())).cloned());
    Ok(Proxy {
        name: o.get("tag").and_then(Value::as_str).unwrap_or("").to_string(),
        kind: "wireguard".into(),
        server: peer.get("address").and_then(Value::as_str).ok_or("peer without `address`")?.to_string(),
        port: peer.get("port").and_then(Value::as_u64).and_then(|p| u16::try_from(p).ok()).ok_or("peer without `port`")?,
        args: Vec::new(),
        params: p.params,
    })
}
