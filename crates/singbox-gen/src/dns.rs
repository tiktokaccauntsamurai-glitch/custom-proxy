//! `[General] dns-server` и `[Host]` → секция `dns` sing-box.
//!
//! sing-box: серверы — `dns/transport/*` (формат с `type`, ≥1.12), выбор сервера — `dns/router.go`
//! (ARCHITECTURE.md §4). Мануал Shadowrocket: «修改DNS», «DNS-over-PROXY», «Hosts».
//! Теги: `dns-main` (final), `dns-local` (system/bootstrap), `dns-hosts`, `dns-host-N`, `dns-fakeip` (TUN).
//! fake-ip (только TUN, ARCHITECTURE.md §14): программы получают адрес из 198.18.0.0/15, sing-box по нему
//! восстанавливает домен — узлу уходит домен, а не IP. `[General] always-real-ip` (ключ Shadowrocket) —
//! исключения; `*` = fake-ip выключен. Резолв для правил (`resolve`, direct) fake-ip не получает:
//! `dns/router.go::Lookup` → `matchDNS(allowFakeIP=false)`.
//! `fallback-dns-server` — цепочка evaluate/respond (см. `build`). Фаза 3: `hijack-dns` из [General].

use std::collections::HashSet;

use fmt_shadowrocket::Document;
use serde_json::{json, Map, Value};

pub const MAIN: &str = "dns-main";
pub const LOCAL: &str = "dns-local";
const HOSTS: &str = "dns-hosts";
pub const FAKEIP: &str = "dns-fakeip";

/// Всегда настоящий IP, даже если `always-real-ip` не задан: локальные имена, время, STUN и проверка
/// интернета Windows (NCSI сверяет ответ `dns.msftncsi.com` с точным адресом — с fake-ip «нет интернета»).
const BUILTIN_REAL_IP: &[&str] = &[
    "localhost", "*.lan", "*.local", "*.localdomain", "*.home.arpa", "*.msftconnecttest.com", "*.msftncsi.com",
    "time.windows.com", "time.*.com", "ntp.*", "*.ntp.org", "stun.*",
];

pub struct Dns {
    pub config: Value,
    /// Включён ли fake-ip (TUN без `always-real-ip = *`).
    pub fakeip: bool,
    /// Резолвер для доменов серверов-прокси (не через сам прокси).
    pub domain_resolver: String,
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn split_host_port(s: &str) -> (String, Option<u16>) {
    if let Some(rest) = s.strip_prefix('[') {
        if let Some((h, tail)) = rest.split_once(']') {
            return (h.to_string(), tail.strip_prefix(':').and_then(|p| p.parse().ok()));
        }
    }
    match s.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => (h.to_string(), p.parse().ok()),
        _ => (s.to_string(), None),
    }
}

fn is_ip(host: &str) -> bool {
    host.parse::<std::net::IpAddr>().is_ok()
}

/// Один адрес DNS Shadowrocket (`https://…`, `tls://…`, `1.1.1.1`, `system`) → сервер sing-box.
pub fn server(spec: &str, tag: &str, outbounds: &HashSet<String>) -> Result<Value, String> {
    let (addr, fragment) = match spec.split_once('#') {
        Some((a, f)) => (a.trim(), Some(f)),
        None => (spec.trim(), None),
    };
    if addr.eq_ignore_ascii_case("system") {
        return Ok(json!({"type": "local", "tag": tag}));
    }
    let (kind, rest) = match addr.split_once("://") {
        Some((s, r)) => (s.to_ascii_lowercase(), r),
        None => ("udp".to_string(), addr),
    };
    let kind = match kind.as_str() {
        "https" | "h3" | "tls" | "quic" | "tcp" | "udp" => kind,
        "doh" => "https".into(),
        other => return Err(format!("DNS scheme `{other}` is not supported")),
    };
    let (hostport, path) = match rest.split_once('/') {
        Some((h, p)) => (h, Some(format!("/{p}"))),
        None => (rest, None),
    };
    let (host, port) = split_host_port(hostport);
    let mut m = Map::new();
    m.insert("type".into(), kind.clone().into());
    m.insert("tag".into(), tag.into());
    m.insert("server".into(), host.clone().into());
    if let Some(p) = port {
        m.insert("server_port".into(), p.into());
    }
    if matches!(kind.as_str(), "https" | "h3") {
        m.insert("path".into(), path.unwrap_or_else(|| "/dns-query".into()).into());
    }
    if !is_ip(&host) {
        m.insert("domain_resolver".into(), LOCAL.into());
    }
    // `#proxy` / `#proxy=name` — DNS-over-PROXY.
    for kv in fragment.into_iter().flat_map(|f| f.split('&')) {
        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
        if k == "proxy" {
            let name = if v.is_empty() { "PROXY".to_string() } else { percent_decode(v) };
            let detour = if outbounds.contains(&name) { name } else { "PROXY".to_string() };
            if !outbounds.contains(&detour) {
                return Err("DNS-over-PROXY: no PROXY outbound".into());
            }
            m.insert("detour".into(), detour.into());
        }
    }
    Ok(Value::Object(m))
}

/// Список доменов с шаблонами Shadowrocket → условие DNS-правила sing-box.
fn domain_matcher(items: &[String]) -> Map<String, Value> {
    let (mut exact, mut suffix, mut regex) = (vec![], vec![], vec![]);
    for d in items {
        match d.strip_prefix("*.") {
            Some(rest) if !rest.contains(['*', '?']) => suffix.push(rest.to_string()),
            _ if d.contains(['*', '?']) => regex.push(crate::wildcard_to_regex(d)),
            _ => exact.push(d.clone()),
        }
    }
    let mut m = Map::new();
    for (k, v) in [("domain", exact), ("domain_suffix", suffix), ("domain_regex", regex)] {
        if !v.is_empty() {
            m.insert(k.into(), json!(v));
        }
    }
    m
}

pub fn build(doc: &Document, outbounds: &HashSet<String>, warnings: &mut Vec<String>, tun: bool) -> Dns {
    let mut servers = vec![];
    let main_spec = doc
        .general("dns-server")
        .and_then(|v| v.split(',').map(str::trim).find(|s| !s.is_empty()).map(str::to_string));
    let main = main_spec.as_deref().map(|s| server(s, MAIN, outbounds)).transpose().unwrap_or_else(|e| {
        warnings.push(format!("dns-server: {e}; using default DoH"));
        None
    });
    // По умолчанию — зашифрованный DNS по IP, без системного резолвера.
    let main = main.unwrap_or_else(|| json!({"type": "https", "tag": MAIN, "server": "1.1.1.1", "path": "/dns-query"}));
    let main_via_proxy = main.get("detour").is_some();
    servers.push(main);
    servers.push(json!({"type": "local", "tag": LOCAL}));

    let mut rules = vec![];
    let mut predefined = Map::new();
    let mut extra = 0;
    for (line, key, value) in doc.key_values("Host") {
        if key.starts_with("ssid:") {
            warnings.push(format!("[Host] line {line}: per-SSID DNS is not supported"));
            continue;
        }
        let (field, domain) = match key.strip_prefix("*.") {
            Some(d) => ("domain_suffix", d.to_string()),
            None => ("domain", key.clone()),
        };
        let target = if let Some(spec) = value.strip_prefix("server:") {
            if spec.eq_ignore_ascii_case("system") {
                LOCAL.to_string()
            } else {
                let tag = format!("dns-host-{extra}");
                extra += 1;
                match server(spec, &tag, outbounds) {
                    Ok(s) => servers.push(s),
                    Err(e) => {
                        warnings.push(format!("[Host] line {line}: {e}"));
                        continue;
                    }
                }
                tag
            }
        } else {
            let ips: Vec<&str> = value.split(',').map(str::trim).collect();
            if field != "domain" || !ips.iter().all(|ip| is_ip(ip)) {
                warnings.push(format!("[Host] line {line}: only exact domain → IP mappings are supported"));
                continue;
            }
            predefined.insert(domain.clone(), json!(ips));
            HOSTS.to_string()
        };
        rules.push(json!({field: [domain], "action": "route", "server": target}));
    }
    if !predefined.is_empty() {
        servers.push(json!({"type": "hosts", "tag": HOSTS, "predefined": predefined}));
    }

    // fake-ip — после [Host]: явные сопоставления важнее.
    let mut fakeip = false;
    if tun {
        let real: Vec<String> =
            doc.general("always-real-ip").unwrap_or_default().split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
        if real.iter().any(|d| d == "*") {
            log::debug!(target: "gen::dns", "always-real-ip = * → fake-ip disabled (nodes receive IPs, not domains)");
        } else {
            let mut all: Vec<String> = BUILTIN_REAL_IP.iter().map(|s| s.to_string()).collect();
            all.extend(real);
            let mut cond = domain_matcher(&all);
            cond.insert("action".into(), "route".into());
            cond.insert("server".into(), MAIN.into());
            rules.push(Value::Object(cond));
            rules.push(json!({"query_type": ["A", "AAAA"], "action": "route", "server": FAKEIP}));
            servers.push(json!({"type": "fakeip", "tag": FAKEIP, "inet4_range": "198.18.0.0/15", "inet6_range": "fc00::/18"}));
            fakeip = true;
        }
    }

    // `[General] fallback-dns-server` (мануал: «当覆写 DNS 查询失败或查询时间超过 2 秒，Shadowrocket 会自动回退备用 DNS»):
    // цепочка evaluate → respond (sing-box 1.14, `dns/router.go`, тест `TestDNSEvaluateParallelFallback`):
    // спросить основной с таймаутом 2 с; есть ответ NOERROR/NXDOMAIN — отдать его (NXDOMAIN — не сбой);
    // нет ответа (ошибка, таймаут, SERVFAIL) — следующий сервер; последний — обычный route.
    // Правила идут после [Host] и fake-ip: запросы, пойманные ими, на fallback не попадают.
    let fallback_specs: Vec<String> =
        doc.general("fallback-dns-server").unwrap_or_default().split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    let mut fallback_tags = Vec::new();
    // Последний сервер цепочки — `dns.final` (правило без условий sing-box не принимает, как и в route).
    let mut final_tag = MAIN.to_string();
    for (i, spec) in fallback_specs.iter().enumerate() {
        let tag = format!("dns-fallback-{i}");
        match server(spec, &tag, outbounds) {
            Ok(s) if s["type"] == "local" => fallback_tags.push(LOCAL.to_string()),
            Ok(s) => {
                servers.push(s);
                fallback_tags.push(tag);
            }
            Err(e) => warnings.push(format!("fallback-dns-server `{spec}`: {e}; skipped")),
        }
    }
    if !fallback_tags.is_empty() {
        let mut chain = vec![MAIN.to_string()];
        chain.extend(fallback_tags);
        chain.dedup();
        let last = chain.len() - 1;
        for (i, tag) in chain.iter().enumerate() {
            if i == last {
                final_tag = tag.clone();
                break;
            }
            let name = format!("try-{i}");
            rules.push(json!({"action": "evaluate", "server": tag, "tag": name, "timeout": "2s"}));
            for rcode in ["NOERROR", "NXDOMAIN"] {
                rules.push(json!({"match_response": name, "response_rcode": rcode, "action": "respond"}));
            }
        }
        log::debug!(target: "gen::dns", "fallback chain: {chain:?}");
    }

    for s in &servers {
        log::debug!(target: "gen::dns", "server {}", crate::redact(s));
    }
    for r in &rules {
        log::debug!(target: "gen::dns", "rule {r}");
    }
    let mut config = json!({"servers": servers, "rules": rules, "final": final_tag});
    if doc.general("ipv6").is_some_and(|v| v.eq_ignore_ascii_case("false")) {
        config["strategy"] = "ipv4_only".into();
    } else if doc.general("prefer-ipv6").is_some_and(|v| v.eq_ignore_ascii_case("true")) {
        config["strategy"] = "prefer_ipv6".into();
    }
    if config["rules"].as_array().is_some_and(Vec::is_empty) {
        config.as_object_mut().unwrap().remove("rules");
    }
    // Домены серверов-прокси нельзя резолвить через сам прокси.
    let domain_resolver = if main_via_proxy { LOCAL } else { MAIN }.to_string();
    Dns { config, fakeip, domain_resolver }
}
