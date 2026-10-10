//! Источник узлов («конфиг подключения») → `Vec<core_model::Node>`.
//!
//! Узлы отделены от правил: правила — `.conf` Shadowrocket, узлы — отдельный файл или URL подписки
//! (настройка `connection`, cli/src/settings.rs). Все форматы приводятся к `core_model::Proxy` с ключами
//! Shadowrocket: дальше узел превращает в JSON `singbox-gen/src/outbound.rs` (или `xray.rs` для xhttp).
//! Таблица соответствия полей — docs/MAPPING.md «Источник узлов».
//!
//! Форматы (определяются по содержимому, [`parse`]):
//! - sing-box JSON (`outbounds[].type`) — `singbox.rs`;
//! - Xray JSON (`outbounds[].protocol`, в т. ч. массив конфигов v2rayN) — `xray.rs`;
//! - Clash / Mihomo YAML (`proxies:`) — `clash.rs` (yaml-rust2);
//! - `.conf` Shadowrocket (секция `[Proxy]`);
//! - ссылки `vless:// vmess:// trojan:// ss:// hy2:// tuic:// ...` по одной на строку — `uri.rs`;
//! - base64 от любого из перечисленного (типичная подписка).
//! Вызывается из `cli/src/main.rs::load_nodes` и `classify`.

mod clash;
mod common;
mod singbox;
mod uri;
mod xray;

use core_model::{Node, Proxy};
use serde_json::Value;

pub struct Parsed {
    /// Человекочитаемое имя формата для лога и `cproxy check`.
    pub format: &'static str,
    pub nodes: Vec<Node>,
    /// Что из источника не будет исполнено (пропущенные узлы, неизвестные поля).
    pub warnings: Vec<String>,
}

/// Разбирает источник узлов. `label` — откуда текст (путь или URL без секретов), идёт в `origin`.
pub fn parse(text: &str, label: &str) -> Result<Parsed, String> {
    let mut p = detect(text, label, true)?;
    dedupe(&mut p);
    log::debug!(target: "nodes", "{label}: {} → {} node(s), {} warning(s)", p.format, p.nodes.len(), p.warnings.len());
    Ok(p)
}

fn detect(text: &str, label: &str, allow_b64: bool) -> Result<Parsed, String> {
    let text = text.trim_start_matches('\u{feff}').trim();
    if text.starts_with('{') || text.starts_with('[') && !text.starts_with("[Proxy]") && serde_json::from_str::<Value>(text).is_ok() {
        let v: Value = serde_json::from_str(text).map_err(|e| format!("{label}: invalid JSON: {e}"))?;
        return json(&v, label);
    }
    let doc = fmt_shadowrocket::parse(text);
    if doc.section("Proxy").is_some() {
        let mut out = Parsed { format: "Shadowrocket [Proxy]", nodes: Vec::new(), warnings: Vec::new() };
        for (line, raw) in doc.data_lines("Proxy") {
            match fmt_shadowrocket::parse_proxy(line, raw) {
                Ok(proxy) => out.nodes.push(Node { proxy, origin: format!("{label} [Proxy] line {line}") }),
                Err(e) => out.warnings.push(format!("{label} [Proxy] {e}; node skipped")),
            }
        }
        return Ok(out);
    }
    if text.lines().any(|l| l.trim_end() == "proxies:" || l.starts_with("proxies:")) {
        let docs = yaml_rust2::YamlLoader::load_from_str(text).map_err(|e| format!("{label}: invalid YAML: {e}"))?;
        let v = docs.first().map(common::yaml_to_json).unwrap_or(Value::Null);
        return Ok(collect("Clash YAML", label, clash::proxies(&v)));
    }
    if text.contains("://") {
        let mut out = Parsed { format: "links", nodes: Vec::new(), warnings: Vec::new() };
        for (i, line) in text.lines().map(str::trim).enumerate() {
            if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
                continue;
            }
            match uri::parse_line(line) {
                Ok(proxy) => out.nodes.push(Node { proxy, origin: format!("{label} line {}", i + 1) }),
                // Ссылку целиком не логируем: в ней секреты. Только схема.
                Err(e) => out.warnings.push(format!("{label} line {} ({}://…): {e}; node skipped", i + 1, line.split("://").next().unwrap_or("?"))),
            }
        }
        return Ok(out);
    }
    if allow_b64 {
        if let Some(dec) = common::b64_str(&text.replace(['\r', '\n', ' '], "")) {
            if let Ok(mut p) = detect(&dec, label, false) {
                p.format = match p.format {
                    "links" => "base64 links",
                    f => f,
                };
                return Ok(p);
            }
        }
    }
    Err(format!("{label}: unknown node format (supported: links, base64 subscription, sing-box JSON, Xray JSON, Clash YAML, Shadowrocket [Proxy])"))
}

fn json(v: &Value, label: &str) -> Result<Parsed, String> {
    // Массив полных конфигов Xray (v2rayN custom config).
    if let Some(arr) = v.as_array() {
        let all = arr.iter().flat_map(xray::outbounds).collect();
        return Ok(collect("Xray JSON", label, all));
    }
    let first = v["outbounds"].get(0).or(v["endpoints"].get(0));
    match first {
        Some(o) if o.get("protocol").is_some() => Ok(collect("Xray JSON", label, xray::outbounds(v))),
        Some(_) => Ok(singbox::parse(v, label)),
        None if v.get("outbounds").is_some() => Ok(Parsed { format: "JSON", nodes: Vec::new(), warnings: vec![format!("{label}: empty `outbounds`")] }),
        None => Err(format!("{label}: JSON without `outbounds`")),
    }
}

fn collect(format: &'static str, label: &str, items: Vec<Result<Proxy, (String, String)>>) -> Parsed {
    let mut out = Parsed { format, nodes: Vec::new(), warnings: Vec::new() };
    for (i, r) in items.into_iter().enumerate() {
        match r {
            Ok(proxy) => out.nodes.push(Node { proxy, origin: format!("{label} #{i} ({format})") }),
            Err((name, e)) => out.warnings.push(format!("{label} #{i} `{name}`: {e}; node skipped")),
        }
    }
    out
}

/// Одинаковые имена в подписках обычны: второй и далее получают суффикс ` 2`, ` 3`...
/// (генератор сам пропускает дубликаты, но здесь узлы не должны теряться).
fn dedupe(p: &mut Parsed) {
    let mut seen: Vec<String> = Vec::new();
    for n in &mut p.nodes {
        let base = n.proxy.name.clone();
        let mut name = base.clone();
        let mut i = 2;
        while seen.iter().any(|s| s.eq_ignore_ascii_case(&name)) || name.eq_ignore_ascii_case("DIRECT") {
            name = format!("{base} {i}");
            i += 1;
        }
        if name != base {
            log::debug!(target: "nodes", "duplicate name `{base}` → `{name}`");
            n.proxy.name = name.clone();
        }
        seen.push(name);
    }
}

/// Похоже ли на правила Shadowrocket (для перетаскивания файла на exe: куда сохранить путь).
pub fn looks_like_rules(text: &str) -> bool {
    let doc = fmt_shadowrocket::parse(text);
    ["Rule", "General", "Proxy Group"].iter().any(|s| doc.section(s).is_some())
}

#[cfg(test)]
mod tests;
