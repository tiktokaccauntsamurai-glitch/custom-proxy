//! Ссылки узлов (по одной на строку) → `Proxy` с ключами Shadowrocket.
//!
//! Схемы: vless, vmess (base64-JSON v2rayN и URL-форма), trojan, ss (SIP002 и legacy base64), hysteria2/hy2,
//! hysteria, tuic, socks/socks5, http/https, anytls, wireguard/wg. Параметры query — общепринятые имена
//! (Xray share link standard, v2rayN, sing-box/hysteria2/tuic URI). Неизвестная схема → ошибка строки.
//! Вызывается из `lib.rs::parse` (список ссылок, в т. ч. после base64-декодирования подписки).

use core_model::Proxy;
use serde_json::Value;

use crate::common::{b64_str, pct, transport, B, Transport};

struct Url {
    scheme: String,
    /// userinfo как есть (без %-декодирования: ss/socks могут быть base64).
    user: Option<String>,
    host: String,
    port: u16,
    query: Vec<(String, String)>,
    name: String,
}

impl Url {
    fn q(&self, keys: &[&str]) -> Option<String> {
        keys.iter().find_map(|k| self.query.iter().find(|(qk, _)| qk.eq_ignore_ascii_case(k)).map(|(_, v)| v.clone())).filter(|v| !v.is_empty())
    }
    fn on(&self, keys: &[&str]) -> bool {
        self.q(keys).is_some_and(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
    }
    fn user_dec(&self) -> Option<String> {
        self.user.as_deref().map(pct).filter(|u| !u.is_empty())
    }
}

/// Порт может быть списком/диапазоном (hysteria2 port hopping `443,1000-2000`) — берём первый.
fn parse_port(s: &str) -> u16 {
    let digits: String = s.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().unwrap_or(0)
}

fn split_url(line: &str) -> Result<Url, String> {
    let (scheme, rest) = line.split_once("://").ok_or("not a link")?;
    let (rest, name) = match rest.split_once('#') {
        Some((r, n)) => (r, pct(n).trim().to_string()),
        None => (rest, String::new()),
    };
    let (rest, query) = match rest.split_once('?') {
        Some((r, q)) => (r, q),
        None => (rest, ""),
    };
    let query = query
        .split('&')
        .filter(|kv| !kv.is_empty())
        .map(|kv| {
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            (pct(k), pct(&v.replace('+', "%20")))
        })
        .collect();
    let (user, hostport) = match rest.rfind('@') {
        Some(i) => (Some(rest[..i].to_string()), &rest[i + 1..]),
        None => (None, rest),
    };
    let hostport = hostport.split('/').next().unwrap_or("");
    let (host, port) = if let Some(h) = hostport.strip_prefix('[') {
        let (h, p) = h.split_once(']').ok_or("bad IPv6 host")?;
        (h.to_string(), parse_port(p.trim_start_matches(':')))
    } else {
        match hostport.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), parse_port(p)),
            None => (hostport.to_string(), 0),
        }
    };
    Ok(Url { scheme: scheme.to_ascii_lowercase(), user, host, port, query, name })
}

pub fn parse_line(line: &str) -> Result<Proxy, String> {
    let scheme = line.split_once("://").map(|(s, _)| s.to_ascii_lowercase()).ok_or("not a link")?;
    if scheme == "vmess" {
        let body = line.splitn(2, "://").nth(1).unwrap_or("");
        let body = body.split('#').next().unwrap_or("");
        if !body.contains('@') {
            return vmess_json(body);
        }
    }
    if scheme == "ss" {
        return ss(line);
    }
    let u = split_url(line)?;
    let mut b = match u.scheme.as_str() {
        "vless" | "vmess" | "trojan" => {
            let kind = u.scheme.as_str();
            let mut b = B::new(kind, &u.host, u.port)?;
            b.set("password", u.user_dec().ok_or("missing user id / password")?);
            if kind == "vmess" {
                b.opt("method", u.q(&["encryption", "scy", "security_method"]));
            }
            b.opt("flow", u.q(&["flow"]));
            b.opt("packet-encoding", u.q(&["packetEncoding", "packet_encoding"]));
            let security = u.q(&["security"]).unwrap_or_else(|| if kind == "trojan" { "tls".into() } else { "none".into() });
            tls_params(&mut b, &u, &security);
            transport(&mut b, Transport {
                network: u.q(&["type", "network"]).as_deref(),
                path: u.q(&["path"]),
                host: u.q(&["host"]),
                service: u.q(&["serviceName", "service_name"]),
                mode: u.q(&["mode"]),
                extra: u.q(&["extra"]),
                header: u.q(&["headerType"]).as_deref(),
            })?;
            b
        }
        "hysteria2" | "hy2" => {
            let mut b = B::new("hysteria2", &u.host, u.port)?;
            b.set("password", u.user_dec().or(u.q(&["auth", "password"])).ok_or("missing auth")?);
            b.opt("sni", u.q(&["sni", "peer"]));
            b.flag("skip-cert-verify", u.on(&["insecure", "allowInsecure"]));
            b.opt("alpn", u.q(&["alpn"]).map(|a| a.replace(',', "|")));
            if u.q(&["obfs"]).is_some_and(|o| o.eq_ignore_ascii_case("salamander")) {
                b.opt("obfs-password", u.q(&["obfs-password", "obfs_password"]));
            }
            b.opt("upmbps", u.q(&["upmbps", "up"]));
            b.opt("downmbps", u.q(&["downmbps", "down"]));
            b
        }
        "hysteria" => {
            let mut b = B::new("hysteria", &u.host, u.port)?;
            b.opt("auth", u.q(&["auth", "auth_str"]));
            b.opt("obfsParam", u.q(&["obfsParam", "obfs-password"]));
            b.opt("sni", u.q(&["peer", "sni"]));
            b.flag("skip-cert-verify", u.on(&["insecure", "allowInsecure"]));
            b.opt("alpn", u.q(&["alpn"]).map(|a| a.replace(',', "|")));
            b.opt("upmbps", u.q(&["upmbps", "up"]));
            b.opt("downmbps", u.q(&["downmbps", "down"]));
            b
        }
        "tuic" => {
            let mut b = B::new("tuic", &u.host, u.port)?;
            let user = u.user_dec().ok_or("missing uuid:password")?;
            let (uuid, pass) = user.split_once(':').unwrap_or((&user, ""));
            b.set("uuid", uuid);
            b.set("password", u.q(&["password"]).unwrap_or_else(|| pass.to_string()));
            b.opt("congestion-controller", u.q(&["congestion_control", "congestion-control", "congestion_controller"]));
            b.opt("sni", u.q(&["sni", "peer"]));
            b.flag("skip-cert-verify", u.on(&["allow_insecure", "allowInsecure", "insecure"]));
            b.opt("alpn", u.q(&["alpn"]).map(|a| a.replace(',', "|")));
            b
        }
        "socks" | "socks5" | "http" | "https" => {
            let kind = match u.scheme.as_str() {
                "http" => "http",
                "https" => "https",
                _ => "socks5",
            };
            let mut b = B::new(kind, &u.host, u.port)?;
            if let Some(user) = &u.user {
                // socks:// у v2rayN — base64(user:pass); иначе user:pass с %-кодированием.
                let plain = b64_str(user).filter(|d| d.contains(':')).unwrap_or_else(|| pct(user));
                let (name, pass) = plain.split_once(':').unwrap_or((&plain, ""));
                b.set("username", name);
                b.set("password", pass);
            }
            if kind == "https" {
                b.opt("sni", u.q(&["sni", "peer"]));
                b.flag("skip-cert-verify", u.on(&["insecure", "allowInsecure"]));
            }
            b
        }
        "anytls" => {
            let mut b = B::new("anytls", &u.host, u.port)?;
            b.set("password", u.user_dec().ok_or("missing password")?);
            b.opt("sni", u.q(&["sni", "peer"]));
            b.flag("skip-cert-verify", u.on(&["insecure", "allowInsecure"]));
            b.opt("fp", u.q(&["fp"]));
            b
        }
        "wireguard" | "wg" => {
            let mut b = B::new("wireguard", &u.host, u.port)?;
            b.set("privateKey", u.user_dec().or(u.q(&["privatekey", "private_key", "secretKey"])).ok_or("missing private key")?);
            b.opt("publicKey", u.q(&["publickey", "public_key", "peer_public_key"]));
            b.opt("preSharedKey", u.q(&["presharedkey", "pre_shared_key", "psk"]));
            for a in u.q(&["address", "ip"]).unwrap_or_default().split(',').map(str::trim).filter(|a| !a.is_empty()) {
                b.set(if a.contains(':') { "ipv6" } else { "ip" }, a);
            }
            b.opt("reserved", u.q(&["reserved"]).map(|r| r.replace(',', "/")));
            b.opt("mtu", u.q(&["mtu"]));
            b
        }
        "ssr" => return Err("ShadowsocksR is not supported by sing-box".into()),
        other => return Err(format!("unsupported link scheme `{other}://`")),
    };
    b.name = u.name;
    Ok(b.build())
}

/// security=tls|reality|xtls → tls/sni/alpn/fp/pbk/sid/skip-cert-verify.
fn tls_params(b: &mut B, u: &Url, security: &str) {
    match security.to_ascii_lowercase().as_str() {
        "tls" | "xtls" => b.set("tls", "true"),
        "reality" => {
            b.set("tls", "true");
            b.opt("pbk", u.q(&["pbk", "publicKey"]));
            b.opt("sid", u.q(&["sid", "shortId"]));
        }
        _ => return,
    }
    b.opt("sni", u.q(&["sni", "peer", "serverName"]));
    b.opt("alpn", u.q(&["alpn"]).map(|a| a.replace(',', "|")));
    b.opt("fp", u.q(&["fp", "fingerprint"]));
    b.flag("skip-cert-verify", u.on(&["allowInsecure", "insecure", "allow_insecure"]));
}

/// vmess://base64(JSON) — формат v2rayN: {ps, add, port, id, aid, scy, net, type, host, path, tls, sni, alpn, fp}.
fn vmess_json(body: &str) -> Result<Proxy, String> {
    let text = b64_str(body.trim()).ok_or("vmess: bad base64")?;
    let v: Value = serde_json::from_str(&text).map_err(|e| format!("vmess: bad JSON: {e}"))?;
    let g = |k: &str| crate::common::s(&v[k]);
    let mut b = B::new("vmess", &g("add").unwrap_or_default(), crate::common::port(&v["port"]))?;
    b.name = g("ps").unwrap_or_default();
    b.set("password", g("id").ok_or("vmess: missing id")?);
    b.opt("alterId", g("aid").filter(|a| a != "0"));
    b.opt("method", g("scy"));
    if g("tls").is_some_and(|t| t == "tls" || t == "reality") {
        b.set("tls", "true");
        b.opt("sni", g("sni"));
        b.opt("alpn", g("alpn").map(|a| a.replace(',', "|")));
        b.opt("fp", g("fp"));
        b.opt("pbk", g("pbk"));
        b.opt("sid", g("sid"));
        b.flag("skip-cert-verify", crate::common::truthy(&v["allowInsecure"]));
    }
    let net = g("net");
    let host = g("host").map(|h| h.split(',').next().unwrap_or("").trim().to_string());
    transport(&mut b, Transport {
        network: net.as_deref(),
        path: g("path"),
        host,
        service: None,
        mode: g("mode"),
        extra: None,
        header: g("type").as_deref().filter(|_| matches!(net.as_deref(), None | Some("tcp"))),
    })?;
    Ok(b.build())
}

/// ss:// — SIP002 `ss://base64(method:pass)@host:port/?plugin=...#name`, `ss://method:pass@...`
/// (2022-ключи с %-кодированием) и legacy `ss://base64(method:pass@host:port)#name`.
fn ss(line: &str) -> Result<Proxy, String> {
    let body = &line[5..];
    let (body, name) = match body.split_once('#') {
        Some((b, n)) => (b, pct(n).trim().to_string()),
        None => (body, String::new()),
    };
    let link = if body.contains('@') {
        format!("ss://{body}")
    } else {
        // legacy: всё до '?' — base64.
        let (enc, q) = body.split_once('?').map_or((body, None), |(e, q)| (e, Some(q)));
        let enc = enc.trim_end_matches('/');
        let dec = b64_str(enc).ok_or("ss: bad base64")?;
        format!("ss://{dec}{}", q.map(|q| format!("?{q}")).unwrap_or_default())
    };
    let u = split_url(&link)?;
    let user = u.user.as_deref().ok_or("ss: missing method:password")?;
    let plain = if user.contains(':') { pct(user) } else { b64_str(&pct(user)).ok_or("ss: bad base64 userinfo")? };
    let (method, pass) = plain.split_once(':').ok_or("ss: expected method:password")?;
    let mut b = B::new("ss", &u.host, u.port)?;
    b.set("method", method);
    b.set("password", pass);
    if let Some(plugin) = u.q(&["plugin"]) {
        let mut parts = plugin.split(';');
        let kind = parts.next().unwrap_or("");
        let kv: Vec<(&str, &str)> = parts.map(|p| p.split_once('=').unwrap_or((p, ""))).collect();
        let get = |k: &str| kv.iter().find(|(a, _)| *a == k).map(|(_, v)| v.to_string());
        match kind {
            "obfs-local" | "simple-obfs" => {
                b.set("obfs", get("obfs").unwrap_or_else(|| "http".into()));
                b.opt("obfs-host", get("obfs-host"));
            }
            "v2ray-plugin" => {
                b.set("obfs", "websocket");
                b.opt("obfs-host", get("host"));
                b.opt("path", get("path"));
                b.flag("tls", kv.iter().any(|(k, _)| *k == "tls"));
            }
            "" | "none" => {}
            other => return Err(format!("unsupported ss plugin `{other}`")),
        }
    }
    b.name = name;
    Ok(b.build())
}
