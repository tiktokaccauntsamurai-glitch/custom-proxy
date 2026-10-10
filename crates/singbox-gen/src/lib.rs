//! Конфиг Shadowrocket → конфиг sing-box (≥ 1.14).
//!
//! Семантика повторяет Shadowrocket: правила сверху вниз, sniff SNI/Host
//! (extended-matching), IP-правила без `no-resolve` вызывают резолв,
//! GEOIP идёт после явных правил, FINAL — в конце. Всё, что нельзя
//! исполнить, попадает в `warnings`; правила на недоступные политики
//! превращаются в reject (fail-closed), а не в DIRECT.
//!
//! Карта связей (docs/ARCHITECTURE.md §6):
//! - `outbound.rs` → `outbounds[]`/`endpoints[]`  (sing-box `protocol/*`)
//! - `group_json`  → `selector`/`urltest`          (sing-box `protocol/group`)
//! - `rules.rs`    → `route.rules`, `route.rule_set` (sing-box `route/route.go::matchRule`, `route/rule`)
//! - `dns.rs`      → `dns`                          (sing-box `dns/router.go`, `dns/transport`)
//! - `xray.rs`     → `Output::xray` (конфиг второго ядра для xhttp, ARCHITECTURE.md §11)
//! - `tun_inbound` → `inbounds[tun]` + `route.auto_detect_interface` (sing-box `protocol/tun`, §14)
//! - `generate`    собирает всё + `inbounds[mixed]`, `log`, `route.final`.
//! Вызывается из `cli/src/main.rs::build`; ресурсы даёт `cli/src/store.rs::Cache`.

mod dns;
mod outbound;
mod rules;
mod xray;

use std::collections::HashSet;

use core_model::{Matcher, Node, ParseError, ProxyGroup};
use fmt_shadowrocket::Document;
use serde_json::{json, Map, Value};

pub use rules::{geoip_url, wildcard_to_regex};
pub use xray::needs_xray;

/// Доступ к скачанным RULE-SET / DOMAIN-SET / GEOIP.
/// Генератор сам в сеть не ходит: скачивает `cproxy fetch` (cli/src/store.rs::Cache — реализация),
/// список URL отдаёт [`resource_urls`]. В тестах — `tests.rs::Mem`.
pub trait Resources {
    fn text(&self, url: &str) -> Option<String>;
    /// Путь к локальному файлу (для бинарных .srs).
    fn path(&self, url: &str) -> Option<String>;
}

/// Параметры генерации из CLI. `None` = взять из конфига (`[General] http-listen/socks5-listen`),
/// иначе значение по умолчанию (127.0.0.1:7890). См. `listeners`.
#[derive(Default)]
pub struct Options {
    /// Хост для всех inbound (`--lan` → `0.0.0.0`).
    pub listen: Option<String>,
    /// Порт единого mixed-inbound (`--port`), перекрывает конфиг.
    pub port: Option<u16>,
    /// `None` — логи sing-box полностью выключены (`log.disabled`).
    pub log_level: Option<String>,
    /// Узлы вместо `[Proxy]` из правил (источник `connection`, режимы — cli/src/settings.rs).
    /// `None` — узлы из `[Proxy]` документа.
    pub nodes: Option<Vec<Node>>,
    /// Свободный локальный порт для узла Xray (cli: bind 127.0.0.1:0). `None` — 0 (только для тестов).
    pub alloc_port: Option<fn() -> u16>,
    /// Режим TUN: весь трафик системы через правила (нужны права администратора/root, cli проверяет).
    pub tun: bool,
    /// Доп. исключения из TUN (CIDR): адреса серверов Xray-узлов, разрешённые cli до запуска —
    /// Xray ходит к ним мимо TUN напрямую (ARCHITECTURE.md §14).
    pub tun_exclude: Vec<String>,
}

pub const DEFAULT_LISTEN: &str = "127.0.0.1";
pub const DEFAULT_PORT: u16 = 7890;

pub struct Output {
    pub config: Value,
    pub warnings: Vec<String>,
    /// Происхождение каждого элемента `route.rules` (тот же индекс): строка `.conf` или
    /// служебное правило cproxy. sing-box логирует `match[i]` — cli подставляет отсюда исходную
    /// строку конфига (cli/src/main.rs::pump_sing_box_log, ARCHITECTURE.md §10).
    pub rule_origins: Vec<String>,
    /// Откуда взялся `route.final` (sing-box не пишет `match` для final — только outbound).
    pub final_origin: String,
    /// Человекочитаемые адреса inbound: `mixed 127.0.0.1:7890`.
    pub listeners: Vec<String>,
    /// Те же inbound структурно: (`mixed`|`http`|`socks`, хост, порт) — для системного прокси (cli/src/sysproxy.rs).
    pub inbounds: Vec<(String, String, u16)>,
    /// Конфиг Xray для узлов, которых нет в sing-box (xhttp). `None` — Xray не нужен.
    pub xray: Option<Value>,
}

/// Секреты, которые не должны попадать в логи (debug-лог пишет конфиг целиком).
const SECRET_KEYS: &[&str] =
    &["password", "uuid", "psk", "userkey", "private_key", "pre_shared_key", "auth_str", "secret", "id", "pass", "username"];

/// Копия конфига для лога: секреты → `***`, большие inline rule-set → только счётчик.
pub fn redact(config: &Value) -> Value {
    fn walk(v: &mut Value, in_rule_set: bool) {
        match v {
            Value::Object(m) => {
                for (k, val) in m.iter_mut() {
                    if SECRET_KEYS.contains(&k.as_str()) && val.is_string() {
                        *val = "***".into();
                    } else if in_rule_set && k == "rules" {
                        let n = val.as_array().map_or(0, Vec::len);
                        *val = format!("<{n} headless rules omitted>").into();
                    } else {
                        walk(val, k == "rule_set");
                    }
                }
            }
            Value::Array(a) => a.iter_mut().for_each(|x| walk(x, in_rule_set)),
            _ => {}
        }
    }
    let mut c = config.clone();
    walk(&mut c, false);
    c
}

/// Внешние ресурсы конфига: (url, бинарный ли).
pub fn resource_urls(doc: &Document) -> Result<Vec<(String, bool)>, ParseError> {
    let mut out = Vec::new();
    for (line, r) in doc.data_lines("Rule").zip(doc.rules()?) {
        if let Some(v) = &r.value {
            let m = fmt_shadowrocket::parse_matcher(&r.kind, v).map_err(|message| ParseError { line: line.0, message })?;
            rules::collect_urls(&m, &mut out);
        }
    }
    out.sort();
    out.dedup();
    Ok(out)
}

/// Политика правила → rule action sing-box (`route/rule/rule_action.go`).
enum Policy {
    /// `{"action":"route","outbound":tag}` — финальное действие.
    Route(String),
    /// `{"action":"reject",...}` — финальное; `method: drop` / `no_drop` из REJECT-вариантов.
    Reject(Value),
}

/// Условие «всё»: правило без полей sing-box не принимает, а network-группа покрывает любой трафик.
/// Нужно для `FINAL,REJECT` (route.final может быть только outbound-тегом).
const MATCH_ALL: &str = r#"{"network":["tcp","udp","icmp"]}"#;

/// Shadowrocket сравнивает имена политик без учёта регистра (`YOUTUBE` → группа `YouTube`);
/// точное совпадение имеет приоритет.
fn canonical<'a>(names: impl Iterator<Item = &'a str> + Clone, name: &str) -> Option<String> {
    let mut all = names.clone();
    all.find(|n| *n == name).or_else(|| names.clone().find(|n| n.eq_ignore_ascii_case(name))).map(String::from)
}

fn is_reject(name: &str) -> bool {
    name.to_ascii_uppercase().starts_with("REJECT")
}

struct Ctx {
    tags: HashSet<String>,
    warnings: Vec<String>,
    warned_http_reject: bool,
}

impl Ctx {
    fn policy(&mut self, name: &str) -> Result<Policy, String> {
        let upper = name.to_ascii_uppercase();
        if upper == "DIRECT" {
            return Ok(Policy::Route("DIRECT".into()));
        }
        if is_reject(name) {
            let action = match upper.as_str() {
                "REJECT" => json!({"action": "reject"}),
                "REJECT-DROP" => json!({"action": "reject", "method": "drop"}),
                "REJECT-NO-DROP" => json!({"action": "reject", "no_drop": true}),
                "REJECT-200" | "REJECT-IMG" | "REJECT-TINYGIF" | "REJECT-DICT" | "REJECT-ARRAY" | "REJECT-VIDEO" => {
                    if !self.warned_http_reject {
                        self.warned_http_reject = true;
                        self.warnings.push(format!("{upper} and other HTTP-response rejects act as plain REJECT until the MITM layer"));
                    }
                    json!({"action": "reject"})
                }
                _ => return Err(format!("unknown policy `{name}`")),
            };
            return Ok(Policy::Reject(action));
        }
        canonical(self.tags.iter().map(String::as_str), name)
            .map(Policy::Route)
            .ok_or_else(|| format!("policy `{name}` is unavailable"))
    }

    fn action(&mut self, policy: &str, ctx_line: usize) -> Value {
        match self.policy(policy) {
            Ok(Policy::Route(tag)) => json!({"action": "route", "outbound": tag}),
            Ok(Policy::Reject(a)) => a,
            Err(e) => {
                self.warnings.push(format!("[Rule] line {ctx_line}: {e} → REJECT"));
                json!({"action": "reject"})
            }
        }
    }
}

fn merge(mut cond: Value, action: &Value) -> Value {
    let obj = cond.as_object_mut().expect("rule is an object");
    for (k, v) in action.as_object().expect("action is an object") {
        obj.insert(k.clone(), v.clone());
    }
    cond
}

/// `[General] http-listen` / `socks5-listen` (ключи Surge; в мануале Shadowrocket порта нет —
/// там он в UI «代理共享»). Значения: `7890`, `127.0.0.1:7890`, `[::1]:7890`.
fn parse_listen(v: &str) -> Option<(String, u16)> {
    let v = v.trim();
    if let Ok(p) = v.parse() {
        return Some((DEFAULT_LISTEN.into(), p));
    }
    let (host, port) = v.rsplit_once(':')?;
    Some((host.trim_matches(['[', ']']).to_string(), port.parse().ok()?))
}

/// inbounds: CLI `--port` → один mixed; иначе из конфига (одинаковые адреса или только один ключ →
/// mixed, разные → отдельные http и socks); иначе 127.0.0.1:7890. `--lan` меняет хост у всех.
fn listeners(doc: &Document, opts: &Options, warnings: &mut Vec<String>) -> (Vec<Value>, Vec<String>, Vec<(String, String, u16)>) {
    let read = |key: &str, warnings: &mut Vec<String>| {
        let v = doc.general(key)?;
        let parsed = parse_listen(&v);
        if parsed.is_none() {
            warnings.push(format!("[General] {key} = {v}: expected [host:]port; ignored"));
        }
        parsed
    };
    let http = read("http-listen", warnings);
    let socks = read("socks5-listen", warnings);
    let host = |h: &str| opts.listen.clone().unwrap_or_else(|| h.to_string());
    let mut list: Vec<(&str, String, u16)> = match (opts.port, http, socks) {
        (Some(p), ..) => vec![("mixed", host(DEFAULT_LISTEN), p)],
        (None, Some(h), Some(s)) if h != s => vec![("http", host(&h.0), h.1), ("socks", host(&s.0), s.1)],
        (None, Some(a), _) | (None, None, Some(a)) => vec![("mixed", host(&a.0), a.1)],
        (None, None, None) => vec![("mixed", host(DEFAULT_LISTEN), DEFAULT_PORT)],
    };
    list.dedup();
    let json = list
        .iter()
        .map(|(kind, h, p)| json!({"type": kind, "tag": format!("{kind}-in"), "listen": h, "listen_port": p}))
        .collect();
    let human = list.iter().map(|(kind, h, p)| format!("{kind} {h}:{p}")).collect();
    let structured = list.iter().map(|(kind, h, p)| (kind.to_string(), h.clone(), *p)).collect();
    (json, human, structured)
}

pub fn generate(doc: &Document, res: &dyn Resources, opts: &Options) -> Result<Output, ParseError> {
    log::debug!(target: "gen", "generate: {} sections, sing-box log level {:?}", doc.sections.len(), opts.log_level);
    let mut warnings = Vec::new();
    for s in &doc.sections {
        if fmt_shadowrocket::MITM_SECTIONS.iter().any(|m| m.eq_ignore_ascii_case(&s.name))
            && doc.data_lines(&s.name).next().is_some()
        {
            warnings.push(format!("[{}] is kept for export but not executed yet (MITM phase)", s.name));
        }
    }

    // Шаг 1. Узлы → outbounds/endpoints (outbound.rs), xhttp → Xray (xray.rs). DIRECT всегда первый:
    // sing-box берёт первый outbound как default, если route.final не задан.
    let mut outbounds = vec![json!({"type": "direct", "tag": "DIRECT"})];
    let mut endpoints = Vec::new();
    let mut nodes = Vec::new();
    let mut xray_cfg = xray::Config::new();
    let src = match &opts.nodes {
        Some(list) => list.clone(),
        None => conf_nodes(doc)?,
    };
    for Node { proxy: p, origin } in &src {
        // Параметры узла не логируем целиком: там пароли. Только имя/тип/адрес/ключи.
        let keys: Vec<&str> = p.params.iter().map(|(k, _)| k.as_str()).collect();
        log::debug!(target: "gen::node", "{origin} `{}`: {} {}:{} keys={keys:?}", p.name, p.kind, p.server, p.port);
        if nodes.contains(&p.name) || p.name.eq_ignore_ascii_case("DIRECT") {
            warnings.push(format!("{origin} `{}`: duplicate node name; node skipped", p.name));
            continue;
        }
        let converted = if xray::needs_xray(p) {
            let port = opts.alloc_port.map_or(0, |f| f());
            xray_cfg.add(p, port, &mut warnings).map(|v| {
                log::debug!(target: "gen::node", "`{}` → Xray (xhttp) via socks 127.0.0.1:{port}", p.name);
                outbound::Converted::Outbound(v)
            })
        } else {
            outbound::convert(p)
        };
        match converted {
            Ok(outbound::Converted::Outbound(v)) => {
                log::trace!(target: "gen::node", "`{}` → outbound {}", p.name, redact(&v));
                outbounds.push(v)
            }
            Ok(outbound::Converted::Endpoint(v)) => {
                log::trace!(target: "gen::node", "`{}` → endpoint {}", p.name, redact(&v));
                endpoints.push(v)
            }
            Err(e) => {
                warnings.push(format!("{origin} `{}`: {e}; node skipped", p.name));
                continue;
            }
        }
        nodes.push(p.name.clone());
    }

    // Шаг 2. Группы [Proxy Group] → selector/urltest (group_json). Члены разрешаются без учёта
    // регистра; regex-фильтр добавляет локальные узлы (подписки — фаза 3, DEVLOG).
    let groups_src = doc.groups()?;
    let group_names: HashSet<&str> = groups_src.iter().map(|g| g.name.as_str()).collect();
    let need_proxy = canonical(group_names.iter().copied().chain(nodes.iter().map(String::as_str)), "PROXY").is_none();
    let known = || {
        let synthetic = (need_proxy && !nodes.is_empty()).then_some("PROXY");
        group_names.iter().copied().chain(nodes.iter().map(String::as_str)).chain(synthetic).chain(["DIRECT"])
    };
    let mut groups: Vec<(ProxyGroup, Vec<String>)> = Vec::new();
    for g in &groups_src {
        let mut members = Vec::new();
        for m in &g.members {
            if is_reject(m) {
                warnings.push(format!("group `{}`: `{m}` cannot be a group member in sing-box; skipped", g.name));
            } else if let Some(name) = canonical(known(), m) {
                members.push(name);
            } else {
                warnings.push(format!("group `{}`: unknown member `{m}` (subscriptions are not supported yet); skipped", g.name));
            }
        }
        if let Some(filter) = g.param("policy-regex-filter") {
            match fancy_regex::Regex::new(filter) {
                Ok(re) => {
                    let matched: Vec<String> =
                        nodes.iter().filter(|n| re.is_match(n).unwrap_or(false) && !members.contains(n)).cloned().collect();
                    log::debug!(target: "gen::group", "`{}`: regex `{filter}` matched {matched:?}", g.name);
                    members.extend(matched);
                }
                Err(e) => warnings.push(format!("group `{}`: bad policy-regex-filter: {e}", g.name)),
            }
        }
        log::debug!(target: "gen::group", "`{}` ({}): declared {:?} → resolved {members:?}", g.name, g.kind, g.members);
        groups.push((g.clone(), members));
    }
    // Встроенная политика PROXY = выбор из всех узлов (как «текущий узел» на главном экране).
    if need_proxy && !nodes.is_empty() {
        let g = ProxyGroup { name: "PROXY".into(), kind: "select".into(), members: vec![], params: vec![] };
        groups.push((g, nodes.clone()));
    }
    // Удаляем пустые группы и ссылки на них, пока что-то меняется: sing-box не стартует с пустым
    // selector/urltest или ссылкой на несуществующий тег.
    loop {
        let alive: HashSet<String> =
            groups.iter().filter(|(_, m)| !m.is_empty()).map(|(g, _)| g.name.clone()).chain(nodes.iter().cloned()).chain(["DIRECT".to_string()]).collect();
        let mut changed = false;
        groups.retain(|(g, m)| {
            let keep = !m.is_empty();
            if !keep {
                warnings.push(format!("group `{}` is empty; removed (rules using it → REJECT)", g.name));
                changed = true;
            }
            keep
        });
        for (_, m) in groups.iter_mut() {
            let before = m.len();
            m.retain(|x| alive.contains(x));
            changed |= m.len() != before;
        }
        if !changed {
            break;
        }
    }
    for (g, members) in &groups {
        let v = group_json(g, members, &mut warnings);
        log::trace!(target: "gen::group", "`{}` → {v}", g.name);
        outbounds.push(v);
    }

    let mut ctx = Ctx {
        tags: outbounds.iter().chain(&endpoints).filter_map(|o| o["tag"].as_str().map(String::from)).collect(),
        warnings,
        warned_http_reject: false,
    };

    // Шаг 3. [Rule] → route.rules (порядок и семантика: ARCHITECTURE.md §3).
    let mut conv = rules::Converter::new(res);
    let mut explicit = Vec::new();
    let mut late = Vec::new();
    let mut final_action = None;
    let mut final_origin = String::new();
    for (r, (line, raw)) in doc.rules()?.into_iter().zip(doc.data_lines("Rule")) {
        let origin = format!("[Rule] line {line}: {raw}");
        let action = ctx.action(&r.policy, line);
        let Some(value) = &r.value else {
            log::debug!(target: "gen::rule", "{origin} → route.final ({action})");
            final_action = Some(action);
            final_origin = origin;
            continue;
        };
        let m = fmt_shadowrocket::parse_matcher(&r.kind, value).map_err(|message| ParseError { line, message })?;
        match conv.convert(&m, r.has_option("no-resolve")) {
            Ok(cond) => {
                let geo = matches!(&m, Matcher::Leaf { kind, .. } if kind == "GEOIP");
                let rule = merge(cond.rule, &action);
                log::trace!(target: "gen::rule", "{origin} → {rule} needs_ip={}{}", cond.needs_ip, if geo { " (moved after explicit rules)" } else { "" });
                let entry = (rule, cond.needs_ip, origin);
                if geo { late.push(entry) } else { explicit.push(entry) }
            }
            Err(e) => {
                log::debug!(target: "gen::rule", "{origin} → skipped: {e}");
                ctx.warnings.push(format!("[Rule] line {line}: {e}; rule skipped"))
            }
        }
    }
    // sniff — аналог extended-matching Shadowrocket (домен из SNI/Host); hijack-dns — DNS-запросы,
    // пришедшие как трафик (важно для TUN). Оба не мешают mixed-inbound.
    let mut route_rules = vec![json!({"action": "sniff"}), json!({"protocol": "dns", "action": "hijack-dns"})];
    let mut rule_origins = vec!["(cproxy) sniff: domain from TLS SNI / HTTP Host".to_string(), "(cproxy) hijack-dns".to_string()];
    // TUN ловит и трафик самого Xray до его серверов: без этого правила — петля (Xray → TUN → sing-box →
    // узел-socks → Xray). sing-box свои соединения защищает сам (auto_detect_interface).
    if opts.tun && !xray_cfg.is_empty() {
        route_rules.push(json!({"process_name": ["xray.exe", "xray"], "action": "route", "outbound": "DIRECT"}));
        rule_origins.push("(cproxy) TUN: Xray's own connections go direct (loop protection)".into());
    }
    // Один `resolve` перед первым IP-правилом без no-resolve: домен в Destination сохраняется
    // (route.go::actionResolve), поэтому прокси-узлы по-прежнему резолвят удалённо.
    let mut resolved = false;
    for (rule, needs_ip, origin) in explicit.into_iter().chain(late) {
        if needs_ip && !resolved {
            route_rules.push(json!({"action": "resolve"}));
            rule_origins.push(format!("(cproxy) resolve before first IP rule — {origin}"));
            resolved = true;
        }
        route_rules.push(rule);
        rule_origins.push(origin);
    }
    let final_tag = match final_action {
        Some(a) if a["action"] == "route" => a["outbound"].as_str().unwrap().to_string(),
        Some(reject) => {
            route_rules.push(merge(serde_json::from_str(MATCH_ALL).unwrap(), &reject));
            rule_origins.push(format!("{final_origin} (as match-all reject)"));
            "DIRECT".into()
        }
        None if ctx.tags.contains("PROXY") => {
            final_origin = "(cproxy) no FINAL rule → PROXY".into();
            "PROXY".into()
        }
        None => {
            final_origin = "(cproxy) no FINAL rule and no PROXY → DIRECT".into();
            ctx.warnings.push("no FINAL rule and no PROXY: unmatched traffic goes DIRECT".into());
            "DIRECT".into()
        }
    };
    ctx.warnings.extend(conv.warnings);

    // Шаг 4. DNS (dns.rs, ARCHITECTURE.md §4) и сборка итогового JSON.
    let dns = dns::build(doc, &ctx.tags, &mut ctx.warnings, opts.tun);
    let mut route = Map::new();
    route.insert("rules".into(), route_rules.into());
    if !conv.rule_sets.is_empty() {
        route.insert("rule_set".into(), conv.rule_sets.into());
    }
    route.insert("final".into(), final_tag.into());
    route.insert("default_domain_resolver".into(), dns.domain_resolver.into());
    if opts.tun {
        // Исходящие соединения sing-box привязываются к физическому интерфейсу, а не к своему TUN.
        route.insert("auto_detect_interface".into(), true.into());
    }

    // Логи sing-box идут в stderr без метки времени: cli ставит свою и пишет в общий файл.
    let log = match &opts.log_level {
        Some(level) => json!({"level": level}),
        None => json!({"disabled": true}),
    };
    let (mut inbounds, mut listeners, inbound_list) = listeners(doc, opts, &mut ctx.warnings);
    if opts.tun {
        inbounds.push(tun_inbound(doc, &opts.tun_exclude, &mut ctx.warnings));
        listeners.push(format!("tun {TUN_NAME}{}", if dns.fakeip { " (fake-ip)" } else { "" }));
    }
    log::debug!(target: "gen::listen", "inbounds: {listeners:?}");
    let mut config = json!({
        "log": log,
        "dns": dns.config,
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": route,
    });
    if !endpoints.is_empty() {
        config["endpoints"] = endpoints.into();
    }
    for w in &ctx.warnings {
        log::warn!(target: "gen", "{w}");
    }
    log::debug!(target: "gen", "done: {} outbounds, {} route rules, {} warnings", config["outbounds"].as_array().map_or(0, Vec::len), rule_origins.len(), ctx.warnings.len());
    let xray = (!xray_cfg.is_empty()).then(|| xray_cfg.build(opts.log_level.as_deref()));
    if let Some(x) = &xray {
        log::trace!(target: "gen::xray", "xray config (secrets redacted): {}", redact(x));
    }
    Ok(Output { config, warnings: ctx.warnings, rule_origins, final_origin, listeners, inbounds: inbound_list, xray })
}

/// Узлы из `[Proxy]` документа правил.
pub fn conf_nodes(doc: &Document) -> Result<Vec<Node>, ParseError> {
    Ok(doc
        .proxies()?
        .into_iter()
        .zip(doc.data_lines("Proxy"))
        .map(|(proxy, (line, _))| Node { proxy, origin: format!("[Proxy] line {line}") })
        .collect())
}

pub const TUN_NAME: &str = "cproxy";

/// Inbound TUN (sing-box `option/tun.go`). `auto_route` + `strict_route`: весь трафик через TUN, на Windows
/// strict_route блокирует обход (в т. ч. DNS мимо TUN — `dns_mode` по умолчанию `hijack` при auto_route,
/// sing-box 1.14). `[General] tun-excluded-routes` → `route_exclude_address`, `tun-included-routes` →
/// `route_address` (ключи Shadowrocket). Стек — по умолчанию sing-box (mixed в официальных сборках).
fn tun_inbound(doc: &Document, extra_exclude: &[String], warnings: &mut Vec<String>) -> Value {
    let cidrs = |key: &str, warnings: &mut Vec<String>| -> Vec<String> {
        let mut out = Vec::new();
        for item in doc.general(key).unwrap_or_default().split(',').map(str::trim).filter(|s| !s.is_empty()) {
            let ok = item.split_once('/').is_some_and(|(ip, bits)| ip.parse::<std::net::IpAddr>().is_ok() && bits.parse::<u8>().is_ok());
            if ok {
                out.push(item.to_string());
            } else if item.parse::<std::net::IpAddr>().is_ok() {
                out.push(format!("{item}/{}", if item.contains(':') { 128 } else { 32 }));
            } else {
                warnings.push(format!("[General] {key}: `{item}` is not an IP/CIDR; ignored"));
            }
        }
        out
    };
    let mut t = json!({
        "type": "tun",
        "tag": "tun-in",
        "interface_name": TUN_NAME,
        "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
        "auto_route": true,
        "strict_route": true,
    });
    let mut exclude = cidrs("tun-excluded-routes", warnings);
    // Серверы Xray: иначе его соединения идут Xray → TUN → sing-box → direct, и долгие HTTP/2-потоки xhttp
    // рвутся (лог пользователя: обрывы GET 96% против 68% без TUN, сбои POST).
    for c in extra_exclude {
        if !exclude.contains(c) {
            exclude.push(c.clone());
        }
    }
    if !exclude.is_empty() {
        t["route_exclude_address"] = exclude.into();
    }
    let include = cidrs("tun-included-routes", warnings);
    if !include.is_empty() {
        t["route_address"] = include.into();
    }
    log::debug!(target: "gen::listen", "tun inbound: {t}");
    t
}

/// `C.DefaultURLTestIdleTimeout` в sing-box 1.14.3.
const URLTEST_IDLE_DEFAULT_SECS: u64 = 30 * 60;

fn group_json(g: &ProxyGroup, members: &[String], warnings: &mut Vec<String>) -> Value {
    let kind = g.kind.as_str();
    if kind == "select" || !matches!(kind, "url-test" | "fallback" | "load-balance" | "random") {
        if kind != "select" {
            warnings.push(format!("group `{}`: unknown type `{kind}`, treated as select", g.name));
        }
        let mut v = json!({"type": "selector", "tag": g.name, "outbounds": members});
        let by_name = g.param("policy-select-name").filter(|n| members.iter().any(|m| m == n));
        let by_index = g.param("select").and_then(|i| i.parse::<usize>().ok()).and_then(|i| members.get(i));
        if let Some(d) = by_name.map(str::to_string).or(by_index.cloned()) {
            v["default"] = d.into();
        }
        return v;
    }
    if kind != "url-test" {
        warnings.push(format!("group `{}`: `{kind}` is approximated by url-test", g.name));
    }
    let mut v = json!({"type": "urltest", "tag": g.name, "outbounds": members});
    if let Some(url) = g.param("url") {
        v["url"] = url.into();
    }
    if let Some(i) = g.param("interval").and_then(|i| i.parse::<u64>().ok()) {
        v["interval"] = format!("{i}s").into();
        // sing-box: protocol/group/urltest.go::NewURLTestGroup падает, если interval > idle_timeout
        // (по умолчанию 30 мин, constant/timeout.go). Shadowrocket такого ограничения не имеет.
        if i > URLTEST_IDLE_DEFAULT_SECS {
            v["idle_timeout"] = format!("{i}s").into();
        }
    }
    if let Some(t) = g.param("tolerance").and_then(|t| t.parse::<u64>().ok()) {
        v["tolerance"] = t.into();
    }
    v
}

#[cfg(test)]
mod tests;
