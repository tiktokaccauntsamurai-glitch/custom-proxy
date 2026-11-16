//! Сохранённые настройки: `<data>/settings.json` (store::data_dir).
//!
//! Два независимых конфига (решение пользователя, DEVLOG сессия 4):
//! - `rules` — путь к `.conf` Shadowrocket (правила, группы, DNS, порт);
//! - `connection` — источник узлов: путь к файлу или URL подписки (fmt-nodes). Содержимое подписки
//!   на диск не пишется — только сам URL (секреты в памяти, инвариант CLAUDE.md);
//! - `nodes` — кто управляет узлами: [`NodesMode`];
//! - `system_proxy` — включать ли системный прокси ОС на время `run` (по умолчанию да, sysproxy.rs);
//! - `tun` — режим TUN: весь трафик системы через правила (по умолчанию нет, нужны права администратора);
//! - `selections` — выбор узлов в группах select (`cproxy select`), применяется при следующем запуске;
//! - `kill_switch` — блок всего, кроме ядер, пока запущен cproxy (killswitch.rs, по умолчанию нет);
//! - `mode` — маршрутизация: [`Mode`] (rules / global / strict; ARCHITECTURE.md §21);
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

/// Режим маршрутизации (`cproxy set mode`, `--mode`; решение пользователя 2026-11-16, ARCHITECTURE.md §21).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    /// Правила `.conf` (как «Конфигурация» в Shadowrocket).
    #[default]
    Rules,
    /// Весь трафик и DNS через PROXY, правила не исполняются, напрямую только локальная сеть
    /// (как «Прокси» в Shadowrocket). Захват — как настроено: системный прокси или TUN.
    Global,
    /// Global + TUN + kill switch: сервер недоступен или ядро упало — интернета нет, ничего не уходит мимо.
    Strict,
}

impl Mode {
    pub const NAMES: &'static str = "rules|global|strict";

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.to_ascii_lowercase().as_str() {
            "rules" | "config" => Self::Rules,
            "global" | "proxy" => Self::Global,
            "strict" => Self::Strict,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Rules => "rules",
            Self::Global => "global",
            Self::Strict => "strict",
        }
    }

    /// Правила .conf не исполняются, всё через PROXY (`singbox_gen::Options::global`).
    pub fn global(self) -> bool {
        self != Self::Rules
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
    /// Выбор в группах select (`cproxy select`): группа → узел. Применяется при генерации как `default`.
    pub selections: std::collections::BTreeMap<String, String>,
    /// Kill switch: пока запущен cproxy, в интернет ходят только ядра (killswitch.rs). По умолчанию выключен.
    pub kill_switch: bool,
    /// Маршрутизация: правила / глобальный / строгий. По умолчанию правила.
    pub mode: Mode,
}

impl Default for Settings {
    fn default() -> Self {
        Settings { rules: None, connection: None, nodes: NodesMode::Auto, system_proxy: true, tun: false, debug: false, selections: Default::default(), kill_switch: false, mode: Mode::Rules }
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
            kill_switch: v["kill_switch"].as_bool().unwrap_or(false),
            mode: v["mode"].as_str().and_then(Mode::parse).unwrap_or_default(),
            selections: v["selections"].as_object().map(|m| m.iter().filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_string()))).collect()).unwrap_or_default(),
        };
        log::debug!(target: "settings", "loaded {}: rules={:?} connection={:?} nodes={} system_proxy={} tun={} debug={} kill_switch={} mode={}", p.display(), me.rules, me.connection.as_deref().map(redact_source), me.nodes.name(), me.system_proxy, me.tun, me.debug, me.kill_switch, me.mode.name());
        me
    }

    pub fn save(&self) -> Result<(), String> {
        let p = path();
        std::fs::create_dir_all(p.parent().unwrap()).map_err(|e| e.to_string())?;
        let v = json!({"rules": self.rules, "connection": self.connection, "nodes": self.nodes.name(), "system_proxy": self.system_proxy, "tun": self.tun, "debug": self.debug, "selections": self.selections, "kill_switch": self.kill_switch, "mode": self.mode.name()});
        std::fs::write(&p, serde_json::to_string_pretty(&v).unwrap()).map_err(|e| format!("{}: {e}", p.display()))?;
        log::info!(target: "settings", "saved {}", p.display());
        Ok(())
    }

    pub fn print(&self) {
        println!("rules       {}", self.rules.as_deref().unwrap_or("-"));
        println!("connection  {}", self.connection.as_deref().map(redact_source).unwrap_or("-".into()));
        println!("nodes       {}", self.nodes.name());
        println!("sys-proxy   {}", if self.system_proxy { "on (off while TUN is on)" } else { "off" });
        println!("mode        {}", match self.mode {
            Mode::Rules => "rules (.conf rules)",
            Mode::Global => "global (everything via PROXY, LAN direct; rules not executed)",
            Mode::Strict => "strict (global + TUN + kill switch: no internet without the server)",
        });
        let forced = if self.mode == Mode::Strict { " (forced on by mode strict)" } else { "" };
        println!("tun         {}{}", if self.tun { "on" } else { "off" }, forced);
        println!("debug       {}", if self.debug { "on (full log in <data>/logs)" } else { "off" });
        println!("kill-switch {}{}", if self.kill_switch { "on (only cores reach the internet while cproxy runs)" } else { "off" }, forced);
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
