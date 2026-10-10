//! Условия правил Shadowrocket → headless-правила sing-box и rule-set'ы.
//!
//! sing-box: поля правил — `option/rule.go`, сопоставление — `route/rule/rule_item_*.go`,
//! rule-set — `route/rule/rule_set_local.go` (ARCHITECTURE.md §5). Таблица типов: docs/MAPPING.md «Правила».
//! Скачивание ресурсов — не здесь: `collect_urls` → `lib.rs::resource_urls` → `cli` (`cproxy fetch`).

use std::collections::HashMap;

use core_model::Matcher;
use fmt_shadowrocket::parse_list_line;
use serde_json::{json, Map, Value};

use crate::Resources;

/// Откуда брать бинарные GEOIP rule-set'ы (официальные сборки sing-box).
pub fn geoip_url(code: &str) -> String {
    format!("https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-{}.srs", code.to_ascii_lowercase())
}

fn is_private_geo(code: &str) -> bool {
    matches!(code.to_ascii_uppercase().as_str(), "LAN" | "PRIVATE")
}

/// Внешние ресурсы, нужные условию: (url, бинарный ли).
pub fn collect_urls(m: &Matcher, out: &mut Vec<(String, bool)>) {
    match m {
        Matcher::Leaf { kind, value } => match kind.as_str() {
            "RULE-SET" | "DOMAIN-SET" => out.push((value.clone(), false)),
            "GEOIP" if !is_private_geo(value) => out.push((geoip_url(value), true)),
            _ => {}
        },
        Matcher::And(c) | Matcher::Or(c) => c.iter().for_each(|m| collect_urls(m, out)),
        Matcher::Not(c) => collect_urls(c, out),
    }
}

pub struct Converter<'a> {
    res: &'a dyn Resources,
    /// url → (tag, содержит ли IP-правила)
    sets: HashMap<String, (String, bool)>,
    pub rule_sets: Vec<Value>,
    pub warnings: Vec<String>,
}

/// Условие sing-box и признак «нужен IP назначения» (для вставки `resolve` в `lib.rs::generate`).
/// `rule` — объект без `action`; действие добавляет `lib.rs::merge`.
pub struct Cond {
    pub rule: Value,
    pub needs_ip: bool,
}

fn one(key: &str, v: impl Into<Value>) -> Value {
    let mut m = Map::new();
    m.insert(key.into(), json!([v.into()]));
    Value::Object(m)
}

fn port_cond(prefix: &str, v: &str) -> Result<Value, String> {
    if let Some((a, b)) = v.split_once('-') {
        let (a, b): (u16, u16) = (a.trim().parse().map_err(|_| "bad port")?, b.trim().parse().map_err(|_| "bad port")?);
        return Ok(one(&format!("{prefix}port_range"), format!("{a}:{b}")));
    }
    let p: u16 = v.trim().parse().map_err(|_| format!("bad port `{v}`"))?;
    Ok(one(&format!("{prefix}port"), p))
}

/// `a*c.example?.com` → `^a.*c\.example.\.com$`
pub fn wildcard_to_regex(w: &str) -> String {
    let mut re = String::from("^");
    for c in w.chars() {
        match c {
            '*' => re.push_str(".*"),
            '?' => re.push('.'),
            c if "\\.+()[]{}^$|".contains(c) => {
                re.push('\\');
                re.push(c);
            }
            c => re.push(c),
        }
    }
    re.push('$');
    re
}

impl<'a> Converter<'a> {
    pub fn new(res: &'a dyn Resources) -> Self {
        Self { res, sets: HashMap::new(), rule_sets: Vec::new(), warnings: Vec::new() }
    }

    pub fn convert(&mut self, m: &Matcher, no_resolve: bool) -> Result<Cond, String> {
        match m {
            Matcher::Leaf { kind, value } => self.leaf(kind, value, no_resolve),
            Matcher::And(c) | Matcher::Or(c) => {
                let mode = if matches!(m, Matcher::And(_)) { "and" } else { "or" };
                let mut rules = Vec::new();
                let mut needs_ip = false;
                for child in c {
                    let cond = self.convert(child, no_resolve)?;
                    needs_ip |= cond.needs_ip;
                    rules.push(cond.rule);
                }
                Ok(Cond { rule: json!({"type": "logical", "mode": mode, "rules": rules}), needs_ip })
            }
            Matcher::Not(c) => {
                let mut cond = self.convert(c, no_resolve)?;
                cond.rule["invert"] = true.into();
                Ok(cond)
            }
        }
    }

    fn leaf(&mut self, kind: &str, v: &str, no_resolve: bool) -> Result<Cond, String> {
        let plain = |rule| Ok(Cond { rule, needs_ip: false });
        let ip = |rule| Ok(Cond { rule, needs_ip: !no_resolve });
        match kind {
            "DOMAIN" => plain(one("domain", v)),
            "DOMAIN-SUFFIX" => plain(one("domain_suffix", v.trim_start_matches('.'))),
            "DOMAIN-KEYWORD" => plain(one("domain_keyword", v)),
            "DOMAIN-WILDCARD" => plain(one("domain_regex", wildcard_to_regex(v))),
            "IP-CIDR" | "IP-CIDR6" => ip(one("ip_cidr", v)),
            "SRC-IP" | "SRC-IP-CIDR" => plain(one("source_ip_cidr", v)),
            "DST-PORT" | "DEST-PORT" => plain(port_cond("", v)?),
            "SRC-PORT" => plain(port_cond("source_", v)?),
            "PROCESS-NAME" => plain(one("process_name", v)),
            "PROTOCOL" => match v.to_ascii_uppercase().as_str() {
                "TCP" | "UDP" | "ICMP" => plain(one("network", v.to_ascii_lowercase())),
                "HTTP" => plain(one("protocol", "http")),
                "HTTPS" | "TLS" => plain(one("protocol", "tls")),
                "QUIC" => plain(one("protocol", "quic")),
                "STUN" => plain(one("protocol", "stun")),
                "DNS" => plain(one("protocol", "dns")),
                other => Err(format!("PROTOCOL `{other}` is not supported")),
            },
            "GEOIP" if is_private_geo(v) => ip(json!({"ip_is_private": true})),
            "GEOIP" => {
                let url = geoip_url(v);
                let path = self.res.path(&url).ok_or_else(|| format!("GEOIP {v}: database not downloaded"))?;
                let tag = format!("geoip-{}", v.to_ascii_lowercase());
                if !self.sets.contains_key(&url) {
                    log::debug!(target: "gen::ruleset", "GEOIP {v} → local binary rule-set `{tag}` at {path}");
                    self.rule_sets.push(json!({"type": "local", "tag": tag, "format": "binary", "path": path}));
                    self.sets.insert(url, (tag.clone(), true));
                }
                ip(one("rule_set", tag))
            }
            "RULE-SET" | "DOMAIN-SET" => {
                let (tag, has_ip) = self.list(v, kind == "DOMAIN-SET")?;
                Ok(Cond { rule: one("rule_set", tag), needs_ip: has_ip && !no_resolve })
            }
            "USER-AGENT" | "URL-REGEX" | "SCRIPT" => Err(format!("{kind} needs the HTTP/MITM layer (phase 5)")),
            "IP-ASN" => Err("IP-ASN is not supported by sing-box".into()),
            other => Err(format!("unknown rule type `{other}`")),
        }
    }

    /// Загружает .list из кэша и превращает в inline rule-set.
    /// Домены и IP кладутся в РАЗНЫЕ headless-правила: внутри одного правила sing-box объединяет
    /// поля назначения по ИЛИ, а разные группы полей — по И (ARCHITECTURE.md §5).
    /// Один URL → один тег, даже если на него ссылаются несколько правил.
    fn list(&mut self, url: &str, domain_set: bool) -> Result<(String, bool), String> {
        if let Some(found) = self.sets.get(url) {
            return Ok(found.clone());
        }
        let text = self.res.text(url).ok_or_else(|| format!("{url}: not downloaded"))?;
        let mut domains: Map<String, Value> = Map::new();
        let mut push = |key: &str, v: &str| {
            domains.entry(key).or_insert_with(|| json!([])).as_array_mut().unwrap().push(v.into());
        };
        let (mut ip_cidr, mut src_ip, mut others) = (Vec::new(), Vec::new(), Vec::new());
        // Резолв нужен, только если есть IP-запись без собственного `no-resolve`.
        let mut has_ip = false;
        let mut skipped = 0usize;
        for line in text.lines() {
            let line = line.trim();
            if domain_set {
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                match line.strip_prefix('.') {
                    Some(suffix) => push("domain_suffix", suffix),
                    None => push("domain", line),
                }
                continue;
            }
            let Some((kind, value, opts)) = parse_list_line(line) else { continue };
            match kind.as_str() {
                "DOMAIN" => push("domain", &value),
                "DOMAIN-SUFFIX" => push("domain_suffix", value.trim_start_matches('.')),
                "DOMAIN-KEYWORD" => push("domain_keyword", &value),
                "DOMAIN-WILDCARD" => push("domain_regex", &wildcard_to_regex(&value)),
                "IP-CIDR" | "IP-CIDR6" => {
                    has_ip |= !opts.iter().any(|o| o.eq_ignore_ascii_case("no-resolve"));
                    ip_cidr.push(value)
                }
                "SRC-IP" | "SRC-IP-CIDR" => src_ip.push(value),
                _ => match fmt_shadowrocket::parse_matcher(&kind, &value).and_then(|m| match &m {
                        Matcher::Leaf { kind, .. } if matches!(kind.as_str(), "RULE-SET" | "DOMAIN-SET" | "GEOIP") => {
                            Err("nested sets".to_string())
                        }
                        _ => self.convert(&m, true),
                    }) {
                    Ok(c) => others.push(c.rule),
                    Err(_) => skipped += 1,
                },
            }
        }
        let domain_count: usize = domains.values().filter_map(Value::as_array).map(Vec::len).sum();
        log::debug!(
            target: "gen::ruleset",
            "{url}: {} bytes → {domain_count} domain entries, {} ip_cidr (resolve needed: {has_ip}), {} src ip, {} other rules, {skipped} skipped",
            text.len(), ip_cidr.len(), src_ip.len(), others.len()
        );
        let mut rules = Vec::new();
        if !domains.is_empty() {
            rules.push(Value::Object(domains));
        }
        if !ip_cidr.is_empty() {
            rules.push(json!({"ip_cidr": ip_cidr}));
        }
        if !src_ip.is_empty() {
            rules.push(json!({"source_ip_cidr": src_ip}));
        }
        rules.extend(others);
        if skipped > 0 {
            self.warnings.push(format!("{url}: skipped {skipped} unsupported entries"));
        }
        if rules.is_empty() {
            return Err(format!("{url}: no usable rules"));
        }
        let tag = format!("set-{}", self.sets.len());
        self.rule_sets.push(json!({"type": "inline", "tag": tag, "rules": rules}));
        self.sets.insert(url.to_string(), (tag.clone(), has_ip));
        Ok((tag, has_ip))
    }
}
