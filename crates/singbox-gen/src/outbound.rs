//! Узел `[Proxy]` Shadowrocket → outbound/endpoint sing-box.
//!
//! Ключи узлов — мануал Shadowrocket «编写本地节点» + синонимы Surge/URI (таблица: docs/MAPPING.md «Узлы»).
//! Поля результата — sing-box `option/<протокол>.go`; регистрация типов — `include/registry.go`
//! (ARCHITECTURE.md §2). Общие блоки: `tls` → `option/tls.go` (`common/tls`),
//! `transport` → `option/v2ray_transport.go` (`transport/v2ray*`).
//! Вызывается из `lib.rs::generate` (шаг 1); ошибка = узел пропускается с warning.

use core_model::Proxy;
use serde_json::{json, Map, Value};

pub enum Converted {
    /// → `outbounds[]`
    Outbound(Value),
    /// → `endpoints[]` (WireGuard с 1.11 — endpoint; тег всё равно годится в группы и правила).
    Endpoint(Value),
}

const SNI: &[&str] = &["peer", "sni", "servername", "tls-host", "tls-name"];
const INSECURE: &[&str] = &["allowInsecure", "skip-cert-verify", "insecure", "skip-common-name-verify"];
const HOST: &[&str] = &["obfs-host", "obfsParam", "host", "ws-host"];
const PATH: &[&str] = &["path", "obfs-uri", "obfs-path", "ws-path", "obfsUri"];

fn base(p: &Proxy, kind: &str) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("type".into(), kind.into());
    m.insert("tag".into(), p.name.clone().into());
    m.insert("server".into(), p.server.clone().into());
    m.insert("server_port".into(), p.port.into());
    if p.flag(&["tfo", "fast-open", "tcp-fast-open"]) {
        m.insert("tcp_fast_open".into(), true.into());
    }
    m
}

fn required<'a>(p: &'a Proxy, keys: &[&str]) -> Result<&'a str, String> {
    p.param(keys).filter(|v| !v.is_empty()).ok_or_else(|| format!("missing `{}`", keys[0]))
}

/// Блок `tls` (sing-box `option/tls.go::OutboundTLSOptions`). `force` — протокол без TLS не работает
/// (trojan, hysteria*, tuic, anytls, https, REALITY).
fn tls(p: &Proxy, force: bool, default_alpn: Option<&str>) -> Option<Value> {
    if !force && !p.flag(&["tls", "over-tls"]) {
        return None;
    }
    let mut t = Map::new();
    t.insert("enabled".into(), true.into());
    if let Some(sni) = p.param(SNI).filter(|s| !s.is_empty()) {
        t.insert("server_name".into(), sni.into());
    }
    if p.flag(INSECURE) {
        t.insert("insecure".into(), true.into());
    }
    let alpn: Vec<&str> = match p.param(&["alpn"]) {
        Some(a) => a.split(['|', ';', ' ']).filter(|s| !s.is_empty()).collect(),
        None => default_alpn.into_iter().collect(),
    };
    if !alpn.is_empty() {
        t.insert("alpn".into(), json!(alpn));
    }
    let fp = p.param(&["fp", "client-fingerprint", "utls"]);
    let pbk = p.param(&["pbk", "publicKey", "public-key", "reality-public-key"]);
    if let Some(pbk) = pbk {
        let mut r = json!({"enabled": true, "public_key": pbk});
        if let Some(sid) = p.param(&["sid", "shortId", "short-id", "reality-short-id"]) {
            r["short_id"] = sid.into();
        }
        t.insert("reality".into(), r);
    }
    // REALITY в sing-box работает только поверх uTLS.
    if fp.is_some() || pbk.is_some() {
        t.insert("utls".into(), json!({"enabled": true, "fingerprint": fp.unwrap_or("chrome")}));
    }
    Some(Value::Object(t))
}

/// Блок `transport` (sing-box `option/v2ray_transport.go`): `obfs=` Shadowrocket → ws/grpc/http/httpupgrade.
/// Для ss `obfs=` значит плагин (см. ветку "ss" в `convert`), а не транспорт.
fn transport(p: &Proxy) -> Result<Option<Value>, String> {
    let host = p.param(HOST).or_else(|| {
        p.param(&["ws-headers"]).and_then(|h| h.split('|').find_map(|kv| kv.strip_prefix("Host:")))
    });
    let path = p.param(PATH);
    let t = match p.param(&["obfs", "network", "transport"]).map(str::to_ascii_lowercase).as_deref() {
        None | Some("none") | Some("tcp") | Some("") => return Ok(None),
        Some("websocket") | Some("ws") => {
            let mut t = json!({"type": "ws", "path": path.unwrap_or("/")});
            if let Some(h) = host {
                t["headers"] = json!({"Host": h});
            }
            t
        }
        Some("grpc") => json!({"type": "grpc", "service_name": p.param(&["grpc-service-name", "serviceName"]).or(path).unwrap_or("")}),
        Some("h2") | Some("http2") | Some("http") => {
            let mut t = json!({"type": "http", "path": path.unwrap_or("/")});
            if let Some(h) = host {
                t["host"] = json!([h]);
            }
            t
        }
        Some("httpupgrade") => json!({"type": "httpupgrade", "path": path.unwrap_or("/"), "host": host.unwrap_or("")}),
        Some(other) => return Err(format!("unsupported transport `{other}`")),
    };
    Ok(Some(t))
}

fn put(m: &mut Map<String, Value>, key: &str, v: Option<Value>) {
    if let Some(v) = v {
        m.insert(key.into(), v);
    }
}

fn user_pass(p: &Proxy) -> (Option<&str>, Option<&str>) {
    let user = p.param(&["username", "user"]).or(p.args.first().map(String::as_str));
    let pass = p.param(&["password"]).or(p.args.get(1).map(String::as_str));
    (user.filter(|s| !s.is_empty()), pass.filter(|s| !s.is_empty()))
}

fn mbps(p: &Proxy, keys: &[&str]) -> Option<u64> {
    p.param(keys).and_then(|v| v.trim_end_matches(|c: char| !c.is_ascii_digit()).parse().ok())
}

pub fn convert(p: &Proxy) -> Result<Converted, String> {
    let kind = p.kind.as_str();
    let mut m = match kind {
        "ss" | "shadowsocks" => {
            let mut m = base(p, "shadowsocks");
            m.insert("method".into(), required(p, &["method", "encrypt-method", "cipher"])?.into());
            m.insert("password".into(), required(p, &["password"])?.into());
            match p.param(&["obfs", "plugin"]).map(str::to_ascii_lowercase).as_deref() {
                Some("http") | Some("tls") => {
                    let mode = p.param(&["obfs"]).unwrap_or("http");
                    let mut opts = format!("obfs={mode}");
                    if let Some(h) = p.param(HOST) {
                        opts += &format!(";obfs-host={h}");
                    }
                    m.insert("plugin".into(), "obfs-local".into());
                    m.insert("plugin_opts".into(), opts.into());
                }
                Some("websocket") | Some("ws") => {
                    let mut opts = "mode=websocket".to_string();
                    if let Some(h) = p.param(HOST) {
                        opts += &format!(";host={h}");
                    }
                    if let Some(path) = p.param(PATH) {
                        opts += &format!(";path={path}");
                    }
                    if p.flag(&["tls"]) {
                        opts += ";tls";
                    }
                    m.insert("plugin".into(), "v2ray-plugin".into());
                    m.insert("plugin_opts".into(), opts.into());
                }
                None | Some("none") | Some("") => {}
                Some(other) => return Err(format!("unsupported ss plugin `{other}`")),
            }
            return Ok(Converted::Outbound(Value::Object(m)));
        }
        "vmess" => {
            let mut m = base(p, "vmess");
            m.insert("uuid".into(), required(p, &["password", "username", "uuid"])?.into());
            m.insert("security".into(), p.param(&["method", "cipher", "security"]).unwrap_or("auto").into());
            if let Some(a) = p.param(&["alterId", "alter-id", "aid"]).and_then(|a| a.parse::<u32>().ok()) {
                m.insert("alter_id".into(), a.into());
            }
            put(&mut m, "tls", tls(p, false, None));
            put(&mut m, "transport", transport(p)?);
            m
        }
        "vless" => {
            let mut m = base(p, "vless");
            m.insert("uuid".into(), required(p, &["password", "username", "uuid"])?.into());
            let flow = p.param(&["flow"]).map(str::to_string).or_else(|| {
                p.param(&["xtls"]).filter(|x| *x == "2").map(|_| "xtls-rprx-vision".to_string())
            });
            put(&mut m, "flow", flow.map(Value::from));
            put(&mut m, "packet_encoding", p.param(&["packet-encoding", "packet_encoding"]).map(Value::from));
            let reality = p.param(&["pbk", "publicKey", "public-key", "reality-public-key"]).is_some();
            put(&mut m, "tls", tls(p, reality, None));
            put(&mut m, "transport", transport(p)?);
            m
        }
        "trojan" => {
            let mut m = base(p, "trojan");
            m.insert("password".into(), required(p, &["password"])?.into());
            put(&mut m, "tls", tls(p, true, None));
            put(&mut m, "transport", transport(p)?);
            m
        }
        "anytls" => {
            let mut m = base(p, "anytls");
            m.insert("password".into(), required(p, &["password"])?.into());
            put(&mut m, "tls", tls(p, true, None));
            m
        }
        "hysteria2" | "hy2" => {
            let mut m = base(p, "hysteria2");
            m.insert("password".into(), required(p, &["auth", "password"])?.into());
            if let Some(o) = p.param(&["obfsParam", "obfs-password", "salamander"]).filter(|s| !s.is_empty()) {
                m.insert("obfs".into(), json!({"type": "salamander", "password": o}));
            }
            put(&mut m, "up_mbps", mbps(p, &["upmbps", "up", "up-speed"]).map(Value::from));
            put(&mut m, "down_mbps", mbps(p, &["downmbps", "down", "down-speed"]).map(Value::from));
            put(&mut m, "tls", tls(p, true, Some("h3")));
            m
        }
        "hysteria" => {
            let mut m = base(p, "hysteria");
            put(&mut m, "auth_str", p.param(&["auth", "auth-str"]).map(Value::from));
            put(&mut m, "obfs", p.param(&["obfsParam", "obfs"]).map(Value::from));
            m.insert("up_mbps".into(), mbps(p, &["upmbps", "up"]).unwrap_or(100).into());
            m.insert("down_mbps".into(), mbps(p, &["downmbps", "down"]).unwrap_or(100).into());
            put(&mut m, "tls", tls(p, true, None));
            m
        }
        "tuic" => {
            let mut m = base(p, "tuic");
            m.insert("uuid".into(), required(p, &["user", "uuid", "username"])?.into());
            m.insert("password".into(), required(p, &["password"])?.into());
            put(
                &mut m,
                "congestion_control",
                p.param(&["congestion-controller", "congestion_control", "congestion-control"]).map(Value::from),
            );
            put(&mut m, "tls", tls(p, true, Some("h3")));
            m
        }
        "http" | "https" => {
            let mut m = base(p, "http");
            let (user, pass) = user_pass(p);
            put(&mut m, "username", user.map(Value::from));
            put(&mut m, "password", pass.map(Value::from));
            put(&mut m, "tls", tls(p, kind == "https", None));
            m
        }
        "socks5" | "socks" | "socks5-tls" => {
            if kind == "socks5-tls" {
                return Err("SOCKS5 over TLS is not supported by sing-box".into());
            }
            let mut m = base(p, "socks");
            m.insert("version".into(), "5".into());
            let (user, pass) = user_pass(p);
            put(&mut m, "username", user.map(Value::from));
            put(&mut m, "password", pass.map(Value::from));
            m
        }
        "ssh" => {
            let mut m = base(p, "ssh");
            let (user, pass) = user_pass(p);
            put(&mut m, "user", user.map(Value::from));
            put(&mut m, "password", pass.map(Value::from));
            put(&mut m, "private_key_path", p.param(&["private-key", "privateKey"]).map(Value::from));
            m
        }
        "snell" => {
            // sing-box (option/snell.go) умеет только клиентов v4 и v6; мануал Shadowrocket описывает v2.
            let mut m = base(p, "snell");
            let version: u8 = p.param(&["version"]).and_then(|v| v.parse().ok()).unwrap_or(0);
            if !matches!(version, 4 | 6) {
                return Err(format!("snell v{version} is not supported by sing-box (only version=4 or 6)"));
            }
            m.insert("version".into(), version.into());
            m.insert("psk".into(), required(p, &["psk", "password"])?.into());
            if version == 4 {
                if let Some(mode) = p.param(&["obfs"]).filter(|o| matches!(*o, "http" | "tls")) {
                    m.insert("obfs_mode".into(), mode.into());
                    put(&mut m, "obfs_host", p.param(&["obfs-host"]).map(Value::from));
                }
            }
            m
        }
        "wireguard" | "wg" => return wireguard(p).map(Converted::Endpoint),
        "juicity" => return Err("`juicity` is not supported by sing-box".into()),
        other => return Err(format!("unknown proxy type `{other}`")),
    };
    m.retain(|_, v| !v.is_null());
    Ok(Converted::Outbound(Value::Object(m)))
}

fn wireguard(p: &Proxy) -> Result<Value, String> {
    let mut address: Vec<String> = Vec::new();
    for key in [&["ip", "self-ip", "address"][..], &["ipv6", "self-ip-v6"][..]] {
        if let Some(ip) = p.param(key) {
            let bits = if ip.contains(':') { "/128" } else { "/32" };
            address.push(if ip.contains('/') { ip.to_string() } else { format!("{ip}{bits}") });
        }
    }
    if address.is_empty() {
        return Err("missing `ip`".into());
    }
    let mut peer = json!({
        "address": p.server,
        "port": p.port,
        "public_key": required(p, &["publicKey", "public-key", "peer-public-key"])?,
        "allowed_ips": ["0.0.0.0/0", "::/0"],
    });
    if let Some(psk) = p.param(&["preSharedKey", "pre-shared-key", "psk"]) {
        peer["pre_shared_key"] = psk.into();
    }
    if let Some(k) = p.param(&["keepalive", "persistent-keepalive"]).and_then(|k| k.parse::<u16>().ok()) {
        peer["persistent_keepalive_interval"] = k.into();
    }
    if let Some(r) = p.param(&["reserved"]) {
        let bytes: Result<Vec<u8>, _> = r.split(['/', ',']).map(|b| b.trim().parse::<u8>()).collect();
        peer["reserved"] = json!(bytes.map_err(|_| "invalid `reserved`")?);
    }
    let mut ep = json!({
        "type": "wireguard",
        "tag": p.name,
        "address": address,
        "private_key": required(p, &["privateKey", "private-key"])?,
        "peers": [peer],
    });
    if let Some(mtu) = p.param(&["mtu"]).and_then(|m| m.parse::<u32>().ok()) {
        ep["mtu"] = mtu.into();
    }
    Ok(ep)
}
