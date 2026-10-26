//! Режим сервера: вход VLESS + REALITY + Vision для Shadowrocket, выход по пользователю (docs/SERVER-MODE.md).
//!
//! Вызывается из `cli/src/main.rs::build` при `run --server`; ключи и пользователей даёт `cli/src/server.rs`.
//! Узлы выхода PROXY собирает обычный [`crate::generate`] (outbound.rs, xray.rs — xhttp через Xray), отсюда
//! заменяются только `inbounds` и `route.rules`.
//!
//! sing-box: вход — `protocol/vless/inbound.go` (пользователь → `metadata.User`, стр. 182), REALITY —
//! `option/tls.go::InboundRealityOptions`, условие — `route/rule/rule_item_auth_user.go`. `ip_is_private`
//! (`rule_item_ip_is_private.go` → `sing/common/network.IsPublicAddr`: private, loopback, multicast,
//! link-local, unspecified) и `ip_cidr` в одном правиле объединяются через ИЛИ (`rule_default.go`,
//! `destinationIPCIDRItems`). ARCHITECTURE.md §15.
//!
//! Выходы (выбирает телефон: у каждого выхода свой UUID):
//! - `ru`  — напрямую с домашнего IP. `resolve` до проверки, чтобы `router.lan` и т. п. не обошли запрет
//!   домашней сети; DNS-запросы телефона отвечает DNS сервера (DoH по умолчанию, dns.rs).
//! - `vps` — через PROXY (узлы подключения, url-test). Без `resolve`: после него узел получил бы IP вместо
//!   домена (`route/conn.go:103`, ARCHITECTURE.md §8); поэтому запрет домашней сети — только для IP-литералов.
//! - `lan` — только домашняя сеть (частные IP-литералы), всё остальное и loopback сервера — reject.
//! Всё, что не подошло, — reject (fail-closed).
//! Clash API (`clash_api`): только 127.0.0.1 со случайным secret — для `cproxy server status`; loopback сервера
//! закрыт для телефонов на всех выходах.

use serde_json::{json, Value};

use crate::{Options, Output, Resources};
use core_model::{Node, ParseError};

pub const INBOUND_TAG: &str = "home-in";
pub const FLOW: &str = "xtls-rprx-vision";

/// Кроме `ip_is_private`: адреса, которые не должны быть доступны телефону ни на каком выходе в интернет.
/// CGNAT провайдера, «эта сеть», диапазон fake-ip/бенчмарков, broadcast.
const BLOCK_ALWAYS: &[&str] = &["0.0.0.0/8", "100.64.0.0/10", "198.18.0.0/15", "255.255.255.255/32"];
/// Сам сервер: Clash API, порты Xray на 127.0.0.1 и т. п. Закрыт и для `lan`.
const LOOPBACK: &[&str] = &["127.0.0.0/8", "::1/128"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    Direct,
    Proxy,
    Lan,
}

impl Exit {
    pub const NAMES: &'static str = "ru|vps|lan";
    pub const ALL: [Exit; 3] = [Exit::Direct, Exit::Proxy, Exit::Lan];

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.to_ascii_lowercase().as_str() {
            "ru" | "direct" | "home" => Self::Direct,
            "vps" | "proxy" => Self::Proxy,
            "lan" => Self::Lan,
            _ => return None,
        })
    }

    /// Короткое имя: суффикс пользователя (`iphone-ru`) и значение в server.json.
    pub fn name(self) -> &'static str {
        match self {
            Self::Direct => "ru",
            Self::Proxy => "vps",
            Self::Lan => "lan",
        }
    }

    /// Имя узла в Shadowrocket.
    pub fn node_name(self) -> &'static str {
        match self {
            Self::Direct => "Дом-RU",
            Self::Proxy => "Дом-VPS",
            Self::Lan => "Дом-LAN",
        }
    }
}

#[derive(Debug, Clone)]
pub struct User {
    /// Имя в логе sing-box и в `auth_user`: `<устройство>-<выход>`.
    pub name: String,
    pub uuid: String,
    pub exit: Exit,
}

#[derive(Debug, Clone)]
pub struct Server {
    pub listen: String,
    pub port: u16,
    /// Сайт-маска REALITY: SNI клиента и адрес, куда сервер проксирует чужие рукопожатия.
    pub mask: String,
    pub mask_port: u16,
    pub private_key: String,
    pub short_ids: Vec<String>,
    pub users: Vec<User>,
    /// Доп. запрет для выходов в интернет (CIDR): внешний IP самого дома — иначе телефон попадёт в
    /// роутер через его WAN-адрес. Заполняет cli (резолв `host`).
    pub block: Vec<String>,
    /// Clash API для `server status`: (адрес 127.0.0.1:порт, secret). `None` — не включать.
    pub clash_api: Option<(String, String)>,
}

struct NoResources;

impl Resources for NoResources {
    fn text(&self, _: &str) -> Option<String> {
        None
    }
    fn path(&self, _: &str) -> Option<String> {
        None
    }
}

/// Группа выхода VPS: самый быстрый из всех узлов подключения (решение пользователя, SERVER-QUESTIONS C2).
const PROXY_GROUP: &str =
    "[Proxy Group]\nPROXY = url-test, url=https://www.gstatic.com/generate_204, interval=600, tolerance=50, policy-regex-filter=.*\n";

pub fn generate(server: &Server, nodes: Vec<Node>, opts: &Options) -> Result<Output, ParseError> {
    log::debug!(target: "gen::server", "server: {}:{} mask {}:{}, {} user(s), {} node(s)", server.listen, server.port, server.mask, server.mask_port, server.users.len(), nodes.len());
    let need_proxy = server.users.iter().any(|u| u.exit == Exit::Proxy);
    // FINAL,DIRECT — только чтобы генератор не предупреждал про клиентский FINAL: правила заменяются ниже.
    let doc = fmt_shadowrocket::parse(&format!("{}[Rule]
FINAL,DIRECT
", if need_proxy { PROXY_GROUP } else { "" }));
    let base = Options {
        nodes: Some(if need_proxy { nodes } else { Vec::new() }),
        log_level: opts.log_level.clone(),
        alloc_port: opts.alloc_port,
        fwmark: opts.fwmark,
        ..Default::default()
    };
    let mut out = crate::generate(&doc, &NoResources, &base)?;
    // Предупреждения генератора он уже записал в лог сам; ниже логируются только новые.
    let logged = out.warnings.len();
    let has_proxy = out.config["outbounds"].as_array().is_some_and(|o| o.iter().any(|o| o["tag"] == "PROXY"));

    let mut rules = vec![json!({"action": "sniff"})];
    let mut origins = vec!["(server) sniff: domain from TLS SNI / HTTP Host (for the log)".to_string()];
    let mut push = |rule: Value, origin: String| {
        log::trace!(target: "gen::server", "{origin} → {rule}");
        rules.push(rule);
        origins.push(origin);
    };
    let mut internet_block: Vec<String> = BLOCK_ALWAYS.iter().map(|s| s.to_string()).collect();
    internet_block.extend(server.block.iter().cloned());
    // Правила — на каждого пользователя отдельно, а не на выход: Clash API отдаёт у соединения только текст
    // сработавшего правила (`experimental/clashapi/connections.go`: `rule`), и `auth_user=iphone-ru` в нём —
    // единственный способ посчитать трафик по устройству (`cproxy server status`).
    for u in &server.users {
        let (exit, users) = (u.exit, [u.name.as_str()]);
        let who = |mut rule: Value| {
            rule["auth_user"] = json!(users);
            rule
        };
        let tag = format!("{} ({})", exit.name(), users.join(", "));
        match exit {
            Exit::Direct => {
                push(who(json!({"protocol": "dns", "action": "hijack-dns"})), format!("(server) {tag}: DNS queries → server DNS"));
                push(who(json!({"action": "resolve"})), format!("(server) {tag}: resolve, so LAN names cannot bypass the LAN ban"));
                push(who(json!({"ip_is_private": true, "ip_cidr": internet_block, "action": "reject"})), format!("(server) {tag}: home network / server itself → REJECT"));
                push(who(json!({"action": "route", "outbound": "DIRECT"})), format!("(server) {tag}: → DIRECT (home IP)"));
            }
            Exit::Proxy => {
                push(who(json!({"ip_is_private": true, "ip_cidr": internet_block, "action": "reject"})), format!("(server) {tag}: home network IP literals → REJECT (no resolve: node gets the domain)"));
                if has_proxy {
                    push(who(json!({"action": "route", "outbound": "PROXY"})), format!("(server) {tag}: → PROXY (VPS)"));
                } else {
                    out.warnings.push(format!("server: exit `vps` for {} has no nodes (set connection) → REJECT", users.join(", ")));
                    push(who(json!({"action": "reject"})), format!("(server) {tag}: no nodes → REJECT (fail-closed)"));
                }
            }
            Exit::Lan => {
                push(who(json!({"ip_cidr": LOOPBACK, "action": "reject"})), format!("(server) {tag}: server loopback → REJECT"));
                push(who(json!({"ip_is_private": true, "action": "route", "outbound": "DIRECT"})), format!("(server) {tag}: home network → DIRECT"));
            }
        }
    }
    let all = serde_json::from_str(crate::MATCH_ALL).expect("MATCH_ALL is JSON");
    push(crate::merge(all, &json!({"action": "reject"})), "(server) anything else → REJECT (fail-closed)".into());

    let users: Vec<Value> = server.users.iter().map(|u| json!({"name": u.name, "uuid": u.uuid, "flow": FLOW})).collect();
    let inbound = json!({
        "type": "vless",
        "tag": INBOUND_TAG,
        "listen": server.listen,
        "listen_port": server.port,
        "users": users,
        "tls": {
            "enabled": true,
            "server_name": server.mask,
            "reality": {
                "enabled": true,
                "handshake": {"server": server.mask, "server_port": server.mask_port},
                "private_key": server.private_key,
                "short_id": server.short_ids,
            }
        }
    });
    log::trace!(target: "gen::server", "inbound {}", crate::redact(&inbound));
    out.config["inbounds"] = json!([inbound]);
    if let Some((addr, secret)) = &server.clash_api {
        out.config["experimental"] = json!({"clash_api": {"external_controller": addr, "secret": secret}});
    }
    out.config["route"]["rules"] = rules.into();
    // final не используется (последнее правило ловит всё), но обязан быть тегом outbound.
    out.config["route"]["final"] = "DIRECT".into();
    out.rule_origins = origins;
    out.final_origin = "(server) unreachable: match-all REJECT is the last rule".into();
    let host = if server.listen.contains(':') { format!("[{}]", server.listen) } else { server.listen.clone() };
    out.listeners = vec![format!("vless+reality {host}:{} (mask {})", server.port, server.mask)];
    out.inbounds = Vec::new();
    for w in &out.warnings[logged..] {
        log::warn!(target: "gen::server", "{w}");
    }
    Ok(out)
}
