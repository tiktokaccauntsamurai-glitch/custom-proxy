//! Сохранённые настройки: `<data>/settings.json` (store::data_dir).
//!
//! Два независимых конфига (решение пользователя, DEVLOG сессия 4):
//! - `rules` — путь к `.conf` Shadowrocket (правила, группы, DNS, порт);
//! - `connection` — источник узлов: путь к файлу или URL подписки (fmt-nodes). Содержимое подписки
//!   на диск не пишется — только сам URL (секреты в памяти, инвариант CLAUDE.md);
//! - `nodes` — кто управляет узлами: [`NodesMode`];
//! - `system_proxy` — включать ли системный прокси ОС на время `run` (по умолчанию да, sysproxy.rs);
//! - `tun` — режим TUN: весь трафик системы через правила (по умолчанию нет, нужны права администратора);
//! - `debug` — полный лог (trace) в `<data>/logs` при каждом запуске (по умолчанию нет; main.rs::file_level).
//! Читает/пишет `main.rs` (команды `set`, `status`, запуск без аргументов, перетаскивание файла).

use std::path::PathBuf;

use serde_json::{json, Value};

/// Откуда брать узлы для групп и политики PROXY.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NodesMode {
    /// `connection`, если он задан, иначе `[Proxy]` из правил.
    #[default]
    Auto,
    /// Только узлы из конфига подключения (`[Proxy]` правил игнорируется).
    Connection,
    /// Только `[Proxy]` из правил.
    Rules,
    /// Оба источника; при совпадении имён побеждает узел из правил.
    Both,
}

impl NodesMode {
    pub const NAMES: &'static str = "auto|connection|rules|both";

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.to_ascii_lowercase().as_str() {
            "auto" => Self::Auto,
            "connection" => Self::Connection,
            "rules" => Self::Rules,
            "both" => Self::Both,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Connection => "connection",
            Self::Rules => "rules",
            Self::Both => "both",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    pub rules: Option<String>,
    pub connection: Option<String>,
    pub nodes: NodesMode,
    pub system_proxy: bool,
    pub tun: bool,
    pub debug: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Settings { rules: None, connection: None, nodes: NodesMode::Auto, system_proxy: true, tun: false, debug: false }
    }
}

fn path() -> PathBuf {
    crate::store::data_dir().join("settings.json")
}

impl Settings {
    pub fn load() -> Self {
        let p = path();
        let Ok(text) = std::fs::read_to_string(&p) else {
            log::debug!(target: "settings", "{} not found: defaults", p.display());
            return Self::default();
        };
        let v: Value = match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(e) => {
                log::warn!(target: "settings", "{}: {e}; using defaults", p.display());
                return Self::default();
            }
        };
        let s = |k: &str| v[k].as_str().filter(|s| !s.is_empty()).map(String::from);
        let me = Settings {
            rules: s("rules"),
            connection: s("connection"),
            nodes: s("nodes").and_then(|n| NodesMode::parse(&n)).unwrap_or_default(),
            system_proxy: v["system_proxy"].as_bool().unwrap_or(true),
            tun: v["tun"].as_bool().unwrap_or(false),
            debug: v["debug"].as_bool().unwrap_or(false),
        };
        log::debug!(target: "settings", "loaded {}: rules={:?} connection={:?} nodes={} system_proxy={} tun={} debug={}", p.display(), me.rules, me.connection.as_deref().map(redact_source), me.nodes.name(), me.system_proxy, me.tun, me.debug);
        me
    }

    pub fn save(&self) -> Result<(), String> {
        let p = path();
        std::fs::create_dir_all(p.parent().unwrap()).map_err(|e| e.to_string())?;
        let v = json!({"rules": self.rules, "connection": self.connection, "nodes": self.nodes.name(), "system_proxy": self.system_proxy, "tun": self.tun, "debug": self.debug});
        std::fs::write(&p, serde_json::to_string_pretty(&v).unwrap()).map_err(|e| format!("{}: {e}", p.display()))?;
        log::info!(target: "settings", "saved {}", p.display());
        Ok(())
    }

    pub fn print(&self) {
        println!("rules       {}", self.rules.as_deref().unwrap_or("-"));
        println!("connection  {}", self.connection.as_deref().map(redact_source).unwrap_or("-".into()));
        println!("nodes       {}", self.nodes.name());
        println!("sys-proxy   {}", if self.system_proxy { "on (off while TUN is on)" } else { "off" });
        println!("tun         {}", if self.tun { "on" } else { "off" });
        println!("debug       {}", if self.debug { "on (full log in <data>/logs)" } else { "off" });
        println!("file        {}", path().display());
    }
}

pub fn is_url(s: &str) -> bool {
    s.starts_with("http://") || s.starts_with("https://")
}

/// URL подписки содержит токен: в лог и на экран — только схема и хост.
pub fn redact_source(s: &str) -> String {
    if !is_url(s) {
        return s.to_string();
    }
    let (scheme, rest) = s.split_once("://").unwrap();
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = host.rsplit('@').next().unwrap_or(host);
    format!("{scheme}://{host}/***")
}

/// Путь из ввода пользователя (перетаскивание в окно даёт кавычки) → абсолютный; URL — как есть.
pub fn normalize(input: &str) -> Result<String, String> {
    let s = input.trim().trim_matches('"').trim();
    if is_url(s) {
        return Ok(s.to_string());
    }
    let p = std::path::absolute(s).map_err(|e| format!("{s}: {e}"))?;
    if !p.is_file() {
        return Err(format!("file not found: {}", p.display()));
    }
    Ok(p.to_string_lossy().into_owned())
}
